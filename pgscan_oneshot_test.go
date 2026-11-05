package certstream

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupGapScanStream(t *testing.T, indexes ...int64) (ctx context.Context, db *PgDB, ls *LogStream) {
	t.Helper()
	var cs *CertStream
	ctx, db, cs = setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/oneshot", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if len(indexes) > 0 {
		if err := insertEntries(ctx, db, streamID, indexes); err != nil {
			t.Fatal(err)
		}
	}
	ls = &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	return
}

func TestContinuousGapScanStopsAtSnapshotEnd(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	newStream := func(url string, indexes []int64) *LogStream {
		t.Helper()
		var streamID int32
		if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
			t.Fatal(err)
		}
		if err := insertEntries(ctx, db, streamID, indexes); err != nil {
			t.Fatal(err)
		}
		ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
		ls.SetGapScanContinuous(true)
		return ls
	}

	complete := newStream("https://example.test/oneshot-complete", []int64{0, 1, 2})
	noFetch := func(context.Context, int64, int64, bool, handleLogEntryFn, *atomic.Int64) (int64, bool) {
		t.Fatal("gap fetch in complete stream")
		return 0, false
	}
	if err := db.scanAndBackfillGapsMode(ctx, complete, noFetch, false, nil, true, nil); err != nil {
		t.Fatal(err)
	}
	if complete.GapScanContinuous() || complete.GapScanIndex.Load() != 0 {
		t.Fatalf("hot-only sweep: continuous=%t, cold position=%d; want false, 0", complete.GapScanContinuous(), complete.GapScanIndex.Load())
	}

	incomplete := newStream("https://example.test/oneshot-incomplete", []int64{0, 2})
	failedFetch := func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		if start != 1 || end != 1 {
			t.Fatalf("gap = %d..%d, want 1..1", start, end)
		}
		remaining.Add(-(end - start + 1))
		return start, false
	}
	if err := db.scanAndBackfillGapsMode(ctx, incomplete, failedFetch, false, nil, false, nil); !errors.Is(err, errGapIncomplete) {
		t.Fatalf("incomplete backfill = %v, want %v", err, errGapIncomplete)
	}
	if incomplete.GapScanContinuous() || incomplete.GapScanIndex.Load() != 3 {
		t.Fatalf("complete sweep with failed fetch: continuous=%t, position=%d; want false, 3", incomplete.GapScanContinuous(), incomplete.GapScanIndex.Load())
	}

	incomplete.SetGapScanContinuous(true)
	resumed := coldScanState{next: 2, end: 2, cursorBlocked: true, wasContinuous: true}
	if err := db.scanAndBackfillGapsMode(ctx, incomplete, noFetch, false, &resumed, false, nil); err != nil {
		t.Fatal(err)
	}
	if incomplete.GapScanContinuous() {
		t.Fatal("resumed sweep did not turn off continuous scanning at its fixed end")
	}

	db.stmtSelectGapWindow = db.Pfx(`SELECT logindex FROM CERTDB_missing_entry`)
	incomplete.SetGapScanContinuous(true)
	if err := db.scanAndBackfillGapsMode(ctx, incomplete, noFetch, false, nil, false, nil); err == nil {
		t.Fatal("failed gap query returned no error")
	}
	if !incomplete.GapScanContinuous() {
		t.Fatal("query failure disabled continuous scanning")
	}
}

func TestGapScanDisableDoesNotStartScheduledScan(t *testing.T) {
	ctx, db, ls := setupGapScanStream(t, 0)
	ls.SetGapScanContinuous(true)
	ls.SetGapScanContinuous(false)
	scanCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go db.rescanGaps(scanCtx, ls, time.Now().Add(time.Hour), &wg)
	defer func() { cancel(); wg.Wait() }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if ls.getGapCh() != nil || ls.GapScanIndex.Load() != 0 {
				t.Fatal("disabled wake started a gap scan before its schedule")
			}
		case <-deadline.C:
			return
		}
	}
}

func TestContinuousGapScanReenableDuringDrain(t *testing.T) {
	ctx, db, ls := setupGapScanStream(t, 0, 2)
	ls.SetGapScanContinuous(true)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFetch := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseFetch()
	fetch := func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		close(entered)
		<-release
		remaining.Add(-(end - start + 1))
		return end + 1, false
	}
	done := make(chan error, 1)
	go func() { done <- db.scanAndBackfillGapsMode(ctx, ls, fetch, false, nil, false, nil) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("scan stopped before fetching its gap: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("gap fetch did not start")
	}
	select {
	case _, open := <-ls.getGapCh():
		if open {
			t.Fatal("unexpected extra queued gap")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("full gap scan did not finish while fetch was pending")
	}
	if ls.GapScanContinuous() {
		t.Fatal("full sweep kept continuous scanning enabled during gap fetch")
	}
	ls.SetGapScanContinuous(true)
	releaseFetch()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gap fetch did not finish")
	}
	if !ls.GapScanContinuous() {
		t.Fatal("completed old sweep disabled a newer continuous request")
	}
}

func TestContinuousGapScanCoversSharedSweepPrefix(t *testing.T) {
	ctx, db, ls := setupGapScanStream(t, 0, 2, 3, 4)
	// A shared pass can be deferred while an older continuous sweep is unfinished.
	cold := coldScanState{next: 2, end: 4, cursorBlocked: true, wasContinuous: true}
	ls.gapCh = make(chan gap, 1)
	db.mu.Lock()
	db.batchCh = []chan *LogEntry{make(chan *LogEntry, 2)}
	db.batchCh[0] <- &LogEntry{}
	db.batchCh[0] <- &LogEntry{}
	db.mu.Unlock()
	if err := db.selectStreamGapsMode(ctx, ls, &cold, false, nil); !errors.Is(err, errGapScanDeferred) {
		t.Fatalf("shared pass = %v, want deferral", err)
	}
	ls.SetGapScanContinuous(true)
	seenGap := false
	fetch := func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		if start != 1 || end != 1 {
			t.Fatalf("gap = %d..%d, want shared-prefix gap 1..1", start, end)
		}
		seenGap = true
		remaining.Add(-1)
		return end + 1, false
	}
	if err := db.scanAndBackfillGapsMode(ctx, ls, fetch, false, &cold, false, nil); err != nil {
		t.Fatal(err)
	}
	if !seenGap || ls.GapScanContinuous() {
		t.Fatalf("shared-prefix gap seen=%t, continuous=%t; want true, false", seenGap, ls.GapScanContinuous())
	}
}
