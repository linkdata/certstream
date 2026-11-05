package certstream

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	complete.gapCh = make(chan gap, 1)
	shared := coldScanState{next: -1, end: -1}
	if err := db.selectStreamGapsMode(ctx, complete, &shared, true, nil); err != nil {
		t.Fatal(err)
	}
	if shared.completeMode != 0 {
		t.Fatal("shared sweep marked a continuous request complete")
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
	resumed := coldScanState{next: 2, end: 2, cursorBlocked: true, sweepMode: incomplete.gapScanMode.Load()}
	if err := db.scanAndBackfillGapsMode(ctx, incomplete, noFetch, false, &resumed, false, nil); err != nil {
		t.Fatal(err)
	}
	if incomplete.GapScanContinuous() || resumed.completeMode == 0 {
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
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/oneshot-wake", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
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

func TestContinuousGapScanReenableWinsDuringDrain(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/oneshot-reenable", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
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
	ls.SetGapScanContinuous(false)
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
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/oneshot-shared-prefix", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.SetGapScanContinuous(true)
	cold := coldScanState{next: 2, end: 4, cursorBlocked: true}
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

func TestGapScanReportsProgressWithinQuery(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/scan-progress", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 30004) AS n`), streamID); err != nil {
		t.Fatal(err)
	}
	db.stmtSelectGapWindow = db.Pfx(`SELECT e.logindex +
  (SELECT 0::bigint FROM pg_sleep(CASE WHEN e.logindex = 25000 THEN 1.5 ELSE 0 END)) AS logindex
FROM CERTDB_entry e WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, gapCh: make(chan gap, 1)}
	done := make(chan error, 1)
	go func() { done <- db.selectStreamGapsMode(ctx, ls, nil, false, nil) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for ls.GapScanIndex.Load() < 20_000 {
		select {
		case <-ticker.C:
		case err := <-done:
			t.Fatalf("scan completed before progress was reported: %v", err)
		case <-deadline.C:
			t.Fatal("no progress reported while the database query was still running")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("query completed before its injected pause ended: %v", err)
	default:
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gap query did not finish")
	}
	if got := ls.GapScanIndex.Load(); got != 30_005 {
		t.Fatalf("final progress = %d, want 30005", got)
	}
	if _, err := db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream SET backfill_logindex = 0 WHERE id = $1`), streamID); err != nil {
		t.Fatal(err)
	}
	db.stmtSelectGapWindow = db.Pfx(`SELECT CASE WHEN e.logindex = 25000
  THEN e.logindex / (e.logindex - 25000) ELSE e.logindex END AS logindex
FROM CERTDB_entry e WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls.gapCh = make(chan gap, 1)
	ls.GapScanIndex.Store(0)
	if err := db.selectStreamGapsMode(ctx, ls, nil, false, nil); err == nil {
		t.Fatal("failing query returned no error")
	}
	if got := ls.GapScanIndex.Load(); got != 10_000 {
		t.Fatalf("progress after query error = %d, want retry position 10000", got)
	}
}
