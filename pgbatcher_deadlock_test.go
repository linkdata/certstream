package certstream

import (
	"context"
	"testing"
	"time"
)

func TestRunBatchRetriesDeadlock(t *testing.T) {
	ctx, db, cs, firstStreamID, _ := cleanTestFixture(t)
	var secondStreamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_stream (url, operator, json)
SELECT 'https://example.com/second-log', operator, '{}' FROM CERTDB_stream WHERE id = $1 RETURNING id`), firstStreamID).Scan(&secondStreamID); err != nil {
		t.Fatal(err)
	}

	// Both transactions acquire a different first lock, wait at a barrier,
	// then request the other's first lock. The wrapper calls the real ingest
	// function after the cycle and remains scoped to this database fixture.
	const wrapperSQL = `
CREATE FUNCTION CERTDB_test_ingest_deadlock(data jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  first_key integer;
BEGIN
  IF (data->0->>'logindex')::bigint = 1 THEN
    first_key := 1;
  ELSE
    first_key := 2;
  END IF;
  PERFORM pg_advisory_xact_lock(18739, first_key);
  PERFORM pg_advisory_xact_lock(18739, first_key + 2);
  PERFORM pg_advisory_xact_lock(18739, 3 - first_key);
  PERFORM CERTDB_ingest_batch(data);
END;
$$;`
	if _, err := db.Exec(ctx, db.Pfx(wrapperSQL)); err != nil {
		t.Fatal(err)
	}
	db.funcIngestBatch = db.Pfx(`SELECT CERTDB_test_ingest_deadlock($1::jsonb)`)

	holder, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := holder.Exec(cleanupCtx, `SELECT pg_advisory_unlock_all()`); err != nil {
			t.Errorf("unlock advisory locks: %v", err)
		}
		holder.Release()
	}()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock(18739, 3), pg_advisory_lock(18739, 4)`); err != nil {
		t.Fatal(err)
	}

	first := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: firstStreamID}
	second := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: secondStreamID}
	expires := time.Now().UTC().Add(24 * time.Hour)
	firstEntry := retentionEntry(t, first, 1, expires)
	secondEntry := retentionEntry(t, second, 2, expires)
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, entry := range []*LogEntry{firstEntry, secondEntry} {
		go func() {
			<-start
			results <- db.runBatch(ctx, []*LogEntry{entry})
		}()
	}
	close(start)

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
		if blocked == 2 {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("only %d batch sessions reached the lock barrier", blocked)
		}
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock(18739, 3), pg_advisory_unlock(18739, 4)`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("batch did not recover from deadlock: %v", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for _, entry := range []*LogEntry{firstEntry, secondEntry} {
		var certID int64
		if err := db.QueryRow(ctx, db.Pfx(`SELECT cert FROM CERTDB_entry WHERE stream = $1 AND logindex = $2`),
			entry.LogStream.Id, entry.LogIndex).Scan(&certID); err != nil {
			t.Fatal(err)
		}
		if certID == 0 {
			t.Errorf("stream %d logindex %d stored without its certificate", entry.LogStream.Id, entry.LogIndex)
		}
	}
}
