package certstream

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func setupGapPrefetchTest(t *testing.T) (ctx context.Context, db *PgDB, ls *LogStream, first, second *LogEntry) {
	t.Helper()
	var cs *CertStream
	var streamID int32
	ctx, db, cs, streamID, _ = cleanTestFixture(t)
	ls = &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.LastIndex.Store(511)
	_, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (seen, cert, logindex, stream)
SELECT now(), 0, n, $1 FROM generate_series(0, 511) AS n WHERE n NOT IN (1, 256)`), streamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
		t.Fatal(err)
	}
	queueTestGaps(ls, []gap{{1, 1}, {256, 256}})
	now := time.Now().UTC()
	first = newGapTestEntry(ls, 1, now)
	first.Signature[0] = 0
	second = newGapTestEntry(ls, 256, now)
	second.Signature[0] = 255
	if db.workerIndexFor(first) == db.workerIndexFor(second) {
		t.Fatal("test entries use the same SHA shard")
	}
	return
}

func gapPrefetchTestFetcher(ls *LogStream, first, second *LogEntry) rawEntriesFetcher {
	return func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (next int64, wanted bool) {
		now := time.Now().UTC()
		for index := start; index <= end; index++ {
			entry := newGapTestEntry(ls, index, now)
			switch index {
			case first.Index():
				entry = first
			case second.Index():
				entry = second
			}
			wanted = handle(ctx, now, entry) || wanted
			remaining.Add(-1)
		}
		return end + 1, wanted
	}
}

func TestBackfillPrefetchOverlapsCommit(t *testing.T) {
	ctx, db, ls, first, second := setupGapPrefetchTest(t)
	shard := db.workerIndexFor(first)
	db.batchMu[shard].Lock()
	locked := true
	defer func() {
		if locked {
			db.batchMu[shard].Unlock()
		}
	}()

	secondFetched := make(chan struct{}, 1)
	fetchEntries := gapPrefetchTestFetcher(ls, first, second)
	fetch := func(ctx context.Context, start, end int64, historical bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		next, wanted := fetchEntries(ctx, start, end, historical, handle, remaining)
		if start == 256 {
			secondFetched <- struct{}{}
		}
		return next, wanted
	}
	done := make(chan error, 1)
	go func() { done <- db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false) }()

	var fetchedWhileBlocked bool
	select {
	case <-secondFetched:
		fetchedWhileBlocked = true
	case <-time.After(5 * time.Second):
	}
	var cursor int64
	var firstStored, secondStored bool
	var queryErr error
	if fetchedWhileBlocked {
		queryErr = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 256)
FROM CERTDB_stream WHERE id = $1`), ls.Id).Scan(&cursor, &firstStored, &secondStored)
	}
	db.batchMu[shard].Unlock()
	locked = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backfill did not finish after commit lock released")
	}
	if !fetchedWhileBlocked {
		t.Fatal("next gap group was not fetched while prior DB commit was blocked")
	}
	if queryErr != nil {
		t.Fatal(queryErr)
	}
	if cursor != 1 || firstStored || secondStored {
		t.Fatalf("before first commit: cursor=%d, stored=(%t,%t); want 1, (false,false)", cursor, firstStored, secondStored)
	}
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 256)
FROM CERTDB_stream WHERE id = $1`), ls.Id).Scan(&cursor, &firstStored, &secondStored); err != nil {
		t.Fatal(err)
	}
	if cursor != 257 || !firstStored || !secondStored {
		t.Fatalf("after commits: cursor=%d, stored=(%t,%t); want 257, (true,true)", cursor, firstStored, secondStored)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
}

func TestBackfillPrefetchDoesNotAdvancePastFailedCommit(t *testing.T) {
	ctx, db, ls, first, second := setupGapPrefetchTest(t)
	installShardIngestProbe(t, db, db.workerIndexFor(first))
	err := db.backfillGapsWithFetcherMode(ctx, ls, gapPrefetchTestFetcher(ls, first, second), nil, false)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22012" {
		t.Fatalf("backfill error = %v, want test shard failure", err)
	}
	var cursor int64
	var firstStored, secondStored bool
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 256)
FROM CERTDB_stream WHERE id = $1`), ls.Id).Scan(&cursor, &firstStored, &secondStored); err != nil {
		t.Fatal(err)
	}
	if cursor != 1 || firstStored || !secondStored {
		t.Fatalf("after first commit failed: cursor=%d, stored=(%t,%t); want 1, (false,true)", cursor, firstStored, secondStored)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
}

func TestBackfillPrefetchCancellationLeavesCursor(t *testing.T) {
	ctx, db, ls, first, second := setupGapPrefetchTest(t)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	shard := db.workerIndexFor(first)
	db.batchMu[shard].Lock()
	locked := true
	defer func() {
		if locked {
			db.batchMu[shard].Unlock()
		}
	}()
	secondFetched := make(chan struct{}, 1)
	fetchEntries := gapPrefetchTestFetcher(ls, first, second)
	fetch := func(ctx context.Context, start, end int64, historical bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		next, wanted := fetchEntries(ctx, start, end, historical, handle, remaining)
		if start == 256 {
			secondFetched <- struct{}{}
		}
		return next, wanted
	}
	done := make(chan error, 1)
	go func() { done <- db.backfillGapsWithFetcherMode(runCtx, ls, fetch, nil, false) }()
	select {
	case <-secondFetched:
	case <-time.After(5 * time.Second):
		cancel()
		db.batchMu[shard].Unlock()
		locked = false
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cleanup backfill error = %v, want context cancellation", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("backfill did not stop during cleanup")
		}
		t.Fatal("next group was not fetched before cancellation")
	}
	cancel()
	db.batchMu[shard].Unlock()
	locked = false
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("backfill error = %v, want context cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backfill did not stop after cancellation")
	}
	var cursor int64
	var firstStored, secondStored bool
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 256)
FROM CERTDB_stream WHERE id = $1`), ls.Id).Scan(&cursor, &firstStored, &secondStored); err != nil {
		t.Fatal(err)
	}
	if cursor != 1 || firstStored || secondStored {
		t.Fatalf("after cancellation: cursor=%d, stored=(%t,%t); want 1, (false,false)", cursor, firstStored, secondStored)
	}
}

func TestBackfillPrefetchReusesDecodedClassicTile(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.LastIndex.Store(511)
	_, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (seen, cert, logindex, stream)
SELECT now(), 0, n, $1 FROM generate_series(0, 511) AS n WHERE n NOT IN (257, 263)`), streamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.backfillSetGapStartIndex(ctx, ls, 257); err != nil {
		t.Fatal(err)
	}
	ls.gapCh = make(chan gap)
	closed := false
	now := time.Now().UTC()
	first := newGapTestEntry(ls, 257, now)
	shard := db.workerIndexFor(first)
	db.batchMu[shard].Lock()
	locked := true
	runCtx, cancel := context.WithCancel(ctx)
	firstFetchDone := make(chan struct{}, 1)
	var calls int
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		calls++
		for index := start; index <= end; index++ {
			entry := newGapTestEntry(ls, index, now)
			if index == 257 {
				entry = first
			}
			handle(ctx, now, entry)
			remaining.Add(-1)
		}
		if calls == 1 {
			firstFetchDone <- struct{}{}
		}
		return end + 1, true
	}
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		if !closed {
			close(ls.gapCh)
		}
		if locked {
			db.batchMu[shard].Unlock()
		}
		if !joined {
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("backfill worker cleanup: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("backfill worker did not stop during cleanup")
			}
		}
	}()
	go func() { done <- db.backfillGapsWithFetcherMode(runCtx, ls, fetch, nil, false) }()
	ls.Backfill.Add(1)
	select {
	case ls.gapCh <- gap{257, 257}:
	case <-time.After(5 * time.Second):
		t.Fatal("first gap was not received")
	}
	select {
	case <-firstFetchDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first tile was not fetched")
	}
	ls.Backfill.Add(1)
	var secondReceived bool
	select {
	case ls.gapCh <- gap{263, 263}:
		secondReceived = true
	case <-time.After(5 * time.Second):
	}
	close(ls.gapCh)
	closed = true
	db.batchMu[shard].Unlock()
	locked = false
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backfill did not finish after commit lock released")
	}
	if !secondReceived {
		t.Fatal("second gap was not received while first commit was blocked")
	}
	if calls != 1 {
		t.Fatalf("classic tile fetches = %d, want 1", calls)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
}
