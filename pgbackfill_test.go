package certstream

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestPgDB_GapLoggingDiscovery(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var logs gapLogCapture
	cs.Config.Logger = &logs
	var operatorID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.com/gap-logging"
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, log: &loglist3.Log{URL: url}, gapCh: make(chan gap, 2)}
	if err := insertStream(ctx, db, url, operatorID, &ls.Id); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, ls.Id, []int64{3, 5}); err != nil {
		t.Fatal(err)
	}
	if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
		t.Fatal(err)
	}
	ls.LastIndex.Store(1007)
	var wg sync.WaitGroup
	wg.Add(1)
	db.selectStreamGaps(ctx, &wg, ls, nil)
	// Leading (1..2) and interior (4) gaps are counted before any fetching.
	if got := db.gaps[ls.Id]; got != (gapCounts{url: url, gaps: 2, entries: 3}) {
		t.Fatalf("discovered gaps = %+v", got)
	}
	db.backfillGapsWithFetcher(ctx, ls, func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		remaining.Add(-((end - start) + 1))
		return end + 1, true
	})
	// Consuming the discovered gaps must not count them again; only the trailing
	// gap (6..1007) adds to the totals.
	if got := db.gaps[ls.Id]; got != (gapCounts{url: url, gaps: 3, entries: 1005}) {
		t.Fatalf("gaps after backfill = %+v", got)
	}
	if got := logs.take(); len(got) != 1 || got[0].message != "certstream: gap" || got[0].fields["length"] != int64(1002) {
		t.Fatalf("immediate logs = %v", got)
	}
	cs.close()
	got := logs.take()
	if len(got) != 1 || got[0].message != "certstream: gaps" || got[0].fields["url"] != url || got[0].fields["stream"] != ls.Id || got[0].fields["gaps"] != int64(3) || got[0].fields["entries"] != int64(1005) {
		t.Fatalf("shutdown logs = %v", got)
	}
	if len(db.gaps) != 0 {
		t.Fatal("shutdown did not flush pending gaps")
	}
}

func TestPgDB_BackfillStartIndex_UsesStoredIndex(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-backfill"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{5, 6, 7}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				if _, err = db.Exec(ctx, db.Pfx(UpdateBackfillIndex),
					int64(42), streamID,
				); err != nil {
					t.Fatalf("update backfill_logindex failed: %v", err)
				} else {
					ls := &LogStream{Id: streamID}
					ls.LastIndex.Store(100)
					var minIndex int64
					var stored bool
					if minIndex, err = db.backfillGetGapStartIndex(ctx, ls); err != nil {
						t.Fatalf("backfillStartIndex failed: %v", err)
					} else if minIndex != 42 {
						t.Fatalf("minIndex = %d, want 42", minIndex)
					} else {
						if _, err = db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream SET backfill_logindex = 0 WHERE id = $1;`),
							streamID,
						); err != nil {
							t.Fatalf("clear backfill_logindex failed: %v", err)
						} else if minIndex, err = db.backfillGetGapStartIndex(ctx, ls); err != nil {
							t.Fatalf("backfillStartIndex without stored failed: %v", err)
						} else if stored {
							t.Fatalf("stored = true, want false")
						} else if minIndex != 5 {
							t.Fatalf("minIndex = %d, want 5", minIndex)
						}
					}
				}
			}
		}
	}
}

func TestPgDB_BackfillGapsUpdatesBackfillIndex(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-backfill-gaps"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else {
				ls := &LogStream{
					LogOperator: &LogOperator{},
					Id:          streamID,
				}
				ls.LastIndex.Store(-1)
				ls.gapCh = make(chan gap, 1)
				g := gap{start: 10, end: 12}
				ls.gapCh <- g
				close(ls.gapCh)

				fetchFn := func(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
					if gapcounter != nil {
						gapcounter.Add(-((end - start) + 1))
					}
					wanted = true
					next = end + 1
					return
				}

				db.backfillGapsWithFetcher(ctx, ls, fetchFn)

				var backfillIndex int64
				if err = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`),
					streamID,
				).Scan(&backfillIndex); err != nil {
					t.Fatalf("select backfill_logindex failed: %v", err)
				} else if backfillIndex != g.end+1 {
					t.Fatalf("backfill_logindex = %d, want %d", backfillIndex, g.end+1)
				}
			}
		}
	}
}

func TestPgDB_BackfillGapsDoesNotAdvanceOnIncompleteFetch(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-backfill-incomplete"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{1, 2, 6}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				ls := &LogStream{
					LogOperator: &LogOperator{},
					Id:          streamID,
				}
				ls.LastIndex.Store(-1)
				ls.gapCh = make(chan gap, 1)
				ls.gapCh <- gap{start: 3, end: 5}
				close(ls.gapCh)

				fetchFn := func(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
					if gapcounter != nil {
						gapcounter.Add(-1)
					}
					next = start + 1
					wanted = true
					return
				}

				db.backfillGapsWithFetcher(ctx, ls, fetchFn)

				var backfillIndex int64
				if err = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`),
					streamID,
				).Scan(&backfillIndex); err != nil {
					t.Fatalf("select backfill_logindex failed: %v", err)
				} else if backfillIndex != 4 {
					t.Fatalf("backfill_logindex = %d, want %d", backfillIndex, 4)
				}
			}
		}
	}
}

func TestPgDB_BackfillGapsStopsAdvancingAfterIncompleteGap(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-backfill-multi-gap"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{1, 2, 6, 10}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				ls := &LogStream{
					LogOperator: &LogOperator{},
					Id:          streamID,
				}
				ls.LastIndex.Store(-1)
				ls.gapCh = make(chan gap, 2)
				ls.gapCh <- gap{start: 3, end: 5}
				ls.gapCh <- gap{start: 7, end: 9}
				close(ls.gapCh)

				fetchFn := func(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
					if gapcounter != nil {
						gapcounter.Add(-1)
					}
					next = end + 1
					if start == 3 {
						next = 4
					}
					wanted = true
					return
				}

				db.backfillGapsWithFetcher(ctx, ls, fetchFn)

				var backfillIndex int64
				if err = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`),
					streamID,
				).Scan(&backfillIndex); err != nil {
					t.Fatalf("select backfill_logindex failed: %v", err)
				} else if backfillIndex != 4 {
					t.Fatalf("backfill_logindex = %d, want %d", backfillIndex, 4)
				}
			}
		}
	}
}
