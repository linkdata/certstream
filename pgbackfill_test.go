package certstream

import (
	"context"
	"sync/atomic"
	"testing"
)

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
					if minIndex, stored, err = db.backfillStartIndex(ctx, ls); err != nil {
						t.Fatalf("backfillStartIndex failed: %v", err)
					} else if !stored {
						t.Fatalf("stored = false, want true")
					} else if minIndex != 42 {
						t.Fatalf("minIndex = %d, want 42", minIndex)
					} else {
						if _, err = db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream SET backfill_logindex = 0 WHERE id = $1;`),
							streamID,
						); err != nil {
							t.Fatalf("clear backfill_logindex failed: %v", err)
						} else if minIndex, stored, err = db.backfillStartIndex(ctx, ls); err != nil {
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
					next = end
					return
				}

				db.backfillGapsWithFetcher(ctx, ls, fetchFn)

				var backfillIndex int64
				if err = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`),
					streamID,
				).Scan(&backfillIndex); err != nil {
					t.Fatalf("select backfill_logindex failed: %v", err)
				} else if backfillIndex != g.start {
					t.Fatalf("backfill_logindex = %d, want %d", backfillIndex, g.start)
				}
			}
		}
	}
}
