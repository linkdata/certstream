package certstream

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestGapCursorAdvancesAfterCommittedShard(t *testing.T) {
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
CREATE FUNCTION CERTDB_test_pause_later_gap(_rows jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF (_rows->0->>'logindex')::bigint = 2 THEN
    PERFORM pg_advisory_xact_lock(18741, 1);
  END IF;
  PERFORM CERTDB_ingest_batch(_rows);
END;
$$;`
	if _, err := db.Exec(ctx, db.Pfx(wrapperSQL)); err != nil {
		t.Fatal(err)
	}
	db.funcIngestBatch = db.Pfx(`SELECT CERTDB_test_pause_later_gap($1::jsonb)`)
	holder, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	locked := true
	defer func() {
		if locked {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if _, err := holder.Exec(cleanupCtx, `SELECT pg_advisory_unlock(18741, 1)`); err != nil {
				t.Errorf("unlock advisory lock: %v", err)
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
	done := make(chan error, 1)
	go func() { done <- db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false) }()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND wait_event_type = 'Lock' AND wait_event = 'advisory'`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked > 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("gap fill completed before later shard blocked: %v", err)
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("later shard did not reach advisory lock")
		}
	}
	var firstStored bool
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1)
FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor, &firstStored); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock(18741, 1)`); err != nil {
		t.Fatal(err)
	}
	locked = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !firstStored || cursor != 2 {
		t.Fatalf("while later shard blocked: first stored=%t, cursor=%d; want true, 2", firstStored, cursor)
	}
}
