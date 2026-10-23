package certstream

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestPgDB_GapLoggingDiscovery(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var logs gapLogCapture
	cs.Logger = &logs
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
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	// Leading (1..2) and interior (4) gaps are counted before any fetching.
	if got := db.gaps[ls.Id]; got != (gapCounts{url: url, gaps: 2, entries: 3}) {
		t.Fatalf("discovered gaps = %+v", got)
	}
	if err := db.backfillGapsWithFetcher(ctx, ls, func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		remaining.Add(-((end - start) + 1))
		return end + 1, true
	}, nil); err != nil {
		t.Fatal(err)
	}
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

func TestPgDB_ScanAndBackfillGapsRepeated(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.com/repeated-gap-scan"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, log: &loglist3.Log{URL: url}}
	ls.LastIndex.Store(-1)
	if err := insertEntries(ctx, db, streamID, []int64{1, 3}); err != nil {
		t.Fatal(err)
	}
	if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
		t.Fatal(err)
	}

	var fetched []gap
	var fetchErr error
	fetch := func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		fetched = append(fetched, gap{start, end})
		for index := start; index <= end; index++ {
			if err := insertEntries(ctx, db, streamID, []int64{index}); err != nil {
				fetchErr = err
				return start, false
			}
		}
		remaining.Add(-((end - start) + 1))
		return end + 1, true
	}
	check := func(want []gap, wantCursor int64) {
		t.Helper()
		if fetchErr != nil {
			t.Fatal(fetchErr)
		}
		if !gapsEqual(fetched, want) {
			t.Fatalf("fetched gaps = %v, want %v", fetched, want)
		}
		if ls.getGapCh() != nil {
			t.Fatal("closed gap channel retained")
		}
		var cursor int64
		if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if cursor != wantCursor {
			t.Fatalf("backfill_logindex = %d, want %d", cursor, wantCursor)
		}
	}

	if err := db.scanAndBackfillGaps(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	check([]gap{{2, 2}}, 3)
	if err := insertEntries(ctx, db, streamID, []int64{5}); err != nil {
		t.Fatal(err)
	}
	if err := db.scanAndBackfillGaps(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	check([]gap{{2, 2}, {4, 4}}, 5)

	if err := insertEntries(ctx, db, streamID, []int64{7}); err != nil {
		t.Fatal(err)
	}
	findGap := db.stmtFindGap
	db.stmtFindGap = `SELECT missing_gap_column`
	if err := db.scanAndBackfillGaps(ctx, ls, fetch); err == nil {
		t.Fatal("invalid gap query did not fail")
	}
	check([]gap{{2, 2}, {4, 4}}, 5)
	db.stmtFindGap = findGap
	if err := db.scanAndBackfillGaps(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	check([]gap{{2, 2}, {4, 4}, {6, 6}}, 7)

	ls.LastIndex.Store(9)
	selectMax := db.stmtSelectMaxIdx
	db.stmtSelectMaxIdx = `SELECT missing_max_column`
	ls.gapCh = make(chan gap)
	close(ls.gapCh)
	if err := db.backfillGapsWithFetcher(ctx, ls, fetch, nil); err == nil {
		t.Fatal("invalid max query did not fail")
	}
	ls.gapCh = nil
	check([]gap{{2, 2}, {4, 4}, {6, 6}}, 7)
	db.stmtSelectMaxIdx = selectMax

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := db.scanAndBackfillGaps(canceled, ls, fetch); err == nil {
		t.Fatal("canceled scan did not fail")
	}
	check([]gap{{2, 2}, {4, 4}, {6, 6}}, 7)

	newURL := "https://example.com/new-gap-stream"
	var newStreamID int32
	if err := insertStream(ctx, db, newURL, operatorID, &newStreamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, newStreamID, []int64{10, 12}); err != nil {
		t.Fatal(err)
	}
	newStream := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: newStreamID, log: &loglist3.Log{URL: newURL}}
	newStream.LastIndex.Store(-1)
	if err := db.backfillSetGapStartIndex(ctx, newStream, 10); err != nil {
		t.Fatal(err)
	}
	var newFetched []gap
	if err := db.scanAndBackfillGaps(ctx, newStream, func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		newFetched = append(newFetched, gap{start, end})
		remaining.Add(-((end - start) + 1))
		return end + 1, true
	}); err != nil {
		t.Fatal(err)
	}
	if !gapsEqual(newFetched, []gap{{11, 11}}) || newStream.getGapCh() != nil {
		t.Fatalf("new stream scan = %v, channel = %v", newFetched, newStream.getGapCh())
	}
}

func TestPgDB_ScanAndBackfillGapsLeadingCursorError(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.com/leading-cursor-error"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{3}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, log: &loglist3.Log{URL: url}}
	ls.LastIndex.Store(-1)
	update := db.stmtUpdateBackfillIdx
	db.stmtUpdateBackfillIdx = `UPDATE missing_cursor_table SET logindex = $1 WHERE id = $2`
	if err := db.scanAndBackfillGaps(ctx, ls, ls.getGapEntries); err == nil {
		t.Fatal("failed leading cursor update did not fail the scan")
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 0 {
		t.Fatalf("backfill_logindex after failed update = %d, want 0", cursor)
	}
	db.stmtUpdateBackfillIdx = update
	if err := db.scanAndBackfillGaps(ctx, ls, ls.getGapEntries); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 3 {
		t.Fatalf("backfill_logindex = %d, want 3", cursor)
	}
}

func TestPgDB_RescanGapsRunsAndStops(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.com/rescan-lifecycle"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{3}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, log: &loglist3.Log{URL: url}}
	ls.LastIndex.Store(-1)
	scanCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go db.rescanGaps(scanCtx, ls, time.Now(), &wg)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var cursor int64
		if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if cursor == 3 {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("scheduled gap scan did not run")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gap rescan worker did not stop after cancellation")
	}
}

func TestNextGapScanAt(t *testing.T) {
	now := time.Unix(0, 0)
	for _, tc := range []struct {
		name string
		err  error
		want time.Duration
	}{
		{name: "success", want: 24 * time.Hour},
		{name: "unfillable gap", err: errGapIncomplete, want: 24 * time.Hour},
		{name: "scan failure", err: context.Canceled, want: time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextGapScanAt(now, tc.err); got != now.Add(tc.want) {
				t.Fatalf("next scan = %v, want %v", got, now.Add(tc.want))
			}
		})
	}
}

func TestPgDB_ScanAndBackfillGapsCanceledFetch(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.com/canceled-gap-fetch"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{1, 3}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, log: &loglist3.Log{URL: url}}
	ls.LastIndex.Store(-1)
	if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
		t.Fatal(err)
	}

	scanCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fetchStarted := make(chan struct{})
	done := make(chan error, 1)
	var hasDeadline bool
	go func() {
		done <- db.scanAndBackfillGaps(scanCtx, ls, func(fetchCtx context.Context, start, end int64, _ bool, _ handleLogEntryFn, _ *atomic.Int64) (int64, bool) {
			deadline, ok := fetchCtx.Deadline()
			hasDeadline = ok && deadline.After(time.Now()) && deadline.Before(time.Now().Add(time.Hour+time.Second))
			close(fetchStarted)
			<-fetchCtx.Done()
			return start, false
		})
	}()
	select {
	case <-fetchStarted:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("gap fetch did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error = %v, want context cancellation", err)
	}
	if !hasDeadline || ls.getGapCh() != nil {
		t.Fatalf("bounded scan = %t, gap channel = %v", hasDeadline, ls.getGapCh())
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 1 {
		t.Fatalf("backfill_logindex = %d, want 1", cursor)
	}

	var retried gap
	if err := db.scanAndBackfillGaps(ctx, ls, func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		retried = gap{start, end}
		remaining.Add(-((end - start) + 1))
		return end + 1, true
	}); err != nil {
		t.Fatal(err)
	}
	if retried != (gap{2, 2}) {
		t.Fatalf("retried gap = %v, want {2 2}", retried)
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

				if err = db.backfillGapsWithFetcher(ctx, ls, fetchFn, nil); err != nil {
					t.Fatal(err)
				}

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

				if err = db.backfillGapsWithFetcher(ctx, ls, fetchFn, nil); !errors.Is(err, errGapIncomplete) {
					t.Fatalf("backfill error = %v, want incomplete gap", err)
				}

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

				if err = db.backfillGapsWithFetcher(ctx, ls, fetchFn, nil); !errors.Is(err, errGapIncomplete) {
					t.Fatalf("backfill error = %v, want incomplete gap", err)
				}

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
