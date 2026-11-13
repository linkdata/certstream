package certstream

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestGapCursorAcrossBlockedShard(t *testing.T) {
	for _, tc := range []struct {
		name       string
		blocked    int64
		wantCursor int64
	}{
		{"first shard blocked", 1, 1},
		{"second shard blocked", 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db, cs, streamID, _ := cleanTestFixture(t)
			if err := insertEntries(ctx, db, streamID, []int64{0, 3}); err != nil {
				t.Fatal(err)
			}
			cs.sendEntryCh = make(chan *LogEntry, 2)
			ls := &LogStream{
				LogOperator: &LogOperator{CertStream: cs},
				Id:          streamID,
				tiledLog:    &loglist3.TiledLog{MonitoringURL: "https://example.test/"},
			}
			ls.LastIndex.Store(3)
			if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
				t.Fatal(err)
			}
			queueTestGaps(ls, []gap{{1, 2}})

			var first, second *LogEntry
			for attempt := 0; attempt < 128; attempt++ {
				first = retentionEntry(t, ls, 1, time.Now().UTC().Add(time.Hour))
				second = retentionEntry(t, ls, 2, time.Now().UTC().Add(time.Hour))
				if db.workerIndexFor(first) < db.workerIndexFor(second) {
					break
				}
			}
			if db.workerIndexFor(first) >= db.workerIndexFor(second) {
				t.Fatal("could not generate entries in ascending SHA shards")
			}
			const wrapperSQL = `
CREATE FUNCTION CERTDB_test_pause_gap(_rows jsonb, _blocked bigint) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF (_rows->0->>'logindex')::bigint = _blocked THEN
    PERFORM pg_advisory_xact_lock(18741, 1);
  END IF;
  PERFORM CERTDB_ingest_batch(_rows);
END;
$$;`
			if _, err := db.Exec(ctx, db.Pfx(wrapperSQL)); err != nil {
				t.Fatal(err)
			}
			db.funcIngestBatch = db.Pfx(fmt.Sprintf(`SELECT CERTDB_test_pause_gap($1::jsonb, %d)`, tc.blocked))
			holder, err := db.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Release()
			locked := true
			started := false
			finished := false
			done := make(chan error, 1)
			defer func() {
				if locked {
					cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					if _, err := holder.Exec(cleanupCtx, `SELECT pg_advisory_unlock(18741, 1)`); err != nil {
						t.Errorf("unlock advisory lock: %v", err)
					}
				}
				if started && !finished {
					select {
					case err := <-done:
						if err != nil {
							t.Errorf("gap fill after cleanup: %v", err)
						}
					case <-time.After(10 * time.Second):
						t.Error("gap fill did not finish after advisory lock released")
					}
				}
			}()
			if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock(18741, 1)`); err != nil {
				t.Fatal(err)
			}
			fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
				for _, entry := range []*LogEntry{first, second} {
					handle(ctx, time.Now(), entry)
					remaining.Add(-1)
				}
				return end + 1, true
			}
			go func() { done <- db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false) }()
			started = true

			deadline := time.NewTimer(10 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			var cursor int64
			var firstStored, secondStored bool
			for {
				var blocked int
				if err := holder.QueryRow(ctx, db.Pfx(`SELECT
(SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
 AND wait_event_type = 'Lock' AND wait_event = 'advisory'),
backfill_logindex,
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 2)
FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&blocked, &cursor, &firstStored, &secondStored); err != nil {
					t.Fatal(err)
				}
				if blocked > 0 && cursor == tc.wantCursor &&
					firstStored == (tc.blocked == 2) && secondStored == (tc.blocked == 1) {
					break
				}
				select {
				case err := <-done:
					finished = true
					t.Fatalf("gap fill finished while shard %d was blocked: %v", tc.blocked, err)
				case <-tick.C:
				case <-deadline.C:
					t.Fatalf("while shard %d blocked: waiters=%d, cursor=%d, stored=(%t,%t); want cursor=%d, other entry stored",
						tc.blocked, blocked, cursor, firstStored, secondStored, tc.wantCursor)
				}
			}
			if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock(18741, 1)`); err != nil {
				t.Fatal(err)
			}
			locked = false
			select {
			case err := <-done:
				finished = true
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 2)
FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor, &firstStored, &secondStored); err != nil {
				t.Fatal(err)
			}
			if cursor != 3 || !firstStored || !secondStored {
				t.Fatalf("completed gap: cursor=%d, stored=(%t,%t); want 3, (true,true)", cursor, firstStored, secondStored)
			}
		})
	}
}
