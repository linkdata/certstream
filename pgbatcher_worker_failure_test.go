package certstream

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestWorkerDoesNotPublishFailedBatch(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	ctx, cancelTimeout := context.WithTimeout(ctx, 15*time.Second)
	defer cancelTimeout()
	cs.mu.Lock()
	cs.sendEntryCh = make(chan *LogEntry, 1)
	cs.mu.Unlock()
	db.funcIngestBatch = `SELECT 1/0 WHERE $1::jsonb IS NOT NULL`
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	le := retentionEntry(t, ls, 1, time.Now().Add(time.Hour))
	if _, store := ls.prepareEntry(ctx, time.Now(), le); !store {
		t.Fatal("entry was not prepared for storage")
	}
	shard := db.workerIndexFor(le)
	workerCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(1)
	go db.worker(workerCtx, &workers, shard)
	t.Cleanup(func() {
		cancel()
		workers.Wait()
	})

	select {
	case db.batchCh[shard] <- le:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	ack := make(chan error, 1)
	select {
	case db.batchCh[shard] <- &LogEntry{flushAck: ack}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-ack:
		assertDivisionByZero(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// The next barrier follows the worker's publication loop.
	select {
	case db.batchCh[shard] <- &LogEntry{flushAck: ack}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-ack:
		if err != nil {
			t.Fatalf("empty flush error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case got := <-cs.getSendEntryCh():
		t.Fatalf("failed batch published index %d", got.LogIndex)
	default:
	}
	var count int
	if err := db.QueryRow(ctx, db.Pfx(`SELECT count(*) FROM CERTDB_entry WHERE stream = $1`), streamID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stored entries = %d, want 0", count)
	}
	if ls.Count.Load() != 0 || ls.LogOperator.Count.Load() != 0 {
		t.Fatalf("counts after failed batch = (%d, %d), want (0, 0)", ls.Count.Load(), ls.LogOperator.Count.Load())
	}
}

func TestFlushWorkersReportsEarlierBatchFailure(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	ctx, cancelTimeout := context.WithTimeout(ctx, 15*time.Second)
	defer cancelTimeout()
	cs.mu.Lock()
	cs.sendEntryCh = make(chan *LogEntry, DbIngestBatchSize)
	cs.mu.Unlock()
	db.funcIngestBatch = `SELECT 1/0 WHERE $1::jsonb IS NOT NULL`
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	le := retentionEntry(t, ls, 1, time.Now().Add(time.Hour))
	le.Signature[0] = 0xff // use the last worker, whose first timer is several seconds away
	shard := db.workerIndexFor(le)
	workerCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(1)
	go db.runWorkers(workerCtx, &workers)
	t.Cleanup(func() {
		cancel()
		workers.Wait()
	})

	for range DbIngestBatchSize {
		if _, store := ls.prepareEntry(ctx, time.Now(), le); !store {
			t.Fatal("entry was not prepared for storage")
		}
		select {
		case db.batchCh[shard] <- le:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	assertDivisionByZero(t, db.flushWorkers(ctx))
	if err := db.flushWorkers(ctx); err != nil {
		t.Fatalf("second empty flush error = %v", err)
	}
	if ls.Count.Load() != 0 || ls.LogOperator.Count.Load() != 0 {
		t.Fatalf("counts after failed batch = (%d, %d), want (0, 0)", ls.Count.Load(), ls.LogOperator.Count.Load())
	}
}

func assertDivisionByZero(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22012" {
		t.Fatalf("error = %v, want SQLSTATE 22012", err)
	}
}
