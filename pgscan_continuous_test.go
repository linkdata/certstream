package certstream

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestLogStreamGapScanContinuous(t *testing.T) {
	ls := &LogStream{}
	if ls.GapScanContinuous() {
		t.Fatal("zero-value stream must use shared gap scanning")
	}
	wake := ls.gapScanWakeCh()
	ls.SetGapScanContinuous(true)
	if !ls.GapScanContinuous() {
		t.Fatal("continuous scanning was not enabled")
	}
	select {
	case <-wake:
	default:
		t.Fatal("enabling did not wake the scanner")
	}
	ls.SetGapScanContinuous(true)
	select {
	case <-wake:
		t.Fatal("unchanged setting woke the scanner")
	default:
	}
	ls.SetGapScanContinuous(false)
	if ls.GapScanContinuous() {
		t.Fatal("continuous scanning was not disabled")
	}
	select {
	case <-wake:
	default:
		t.Fatal("disabling did not wake the scanner")
	}
}

func TestGapScanContinuousWakesPermitWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := &PgDB{gapScanPermit: make(chan struct{}, 1)}
		db.gapScanPermit <- struct{}{}
		ls := &LogStream{LogOperator: &LogOperator{}, gapCh: make(chan gap, 1)}
		done := make(chan error, 1)
		go func() { done <- db.selectStreamGapsMode(t.Context(), ls, nil, false, nil) }()
		synctest.Wait()
		ls.SetGapScanContinuous(true)
		synctest.Wait()
		if err := <-done; !errors.Is(err, errGapScanDeferred) {
			t.Fatalf("permit wait after enable = %v, want deferral", err)
		}
	})
}

func TestGapScanContinuousIgnoresStaleWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := &PgDB{gapScanPermit: make(chan struct{}, 1)}
		db.gapScanPermit <- struct{}{}
		ls := &LogStream{LogOperator: &LogOperator{}, gapCh: make(chan gap, 1)}
		ls.SetGapScanContinuous(true)
		ls.SetGapScanContinuous(false)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- db.selectStreamGapsMode(ctx, ls, nil, false, nil) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("stale wake ended permit wait: %v", err)
		default:
		}
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled permit wait = %v, want context canceled", err)
		}
	})
}

func TestGapScanContinuousWakesBlockedSharedGap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ls := &LogStream{}
		done := make(chan error, 1)
		go func() {
			done <- (&PgDB{}).queueGap(t.Context(), ls, make(chan gap), gap{start: 1, end: 1}, false, false)
		}()
		synctest.Wait()
		ls.SetGapScanContinuous(true)
		synctest.Wait()
		if err := <-done; !errors.Is(err, errGapScanDeferred) {
			t.Fatalf("blocked shared gap after enable = %v, want deferral", err)
		}
		if got := ls.Backfill.Load(); got != 0 {
			t.Fatalf("Backfill after deferral = %d, want 0", got)
		}
	})
}

func TestGapScanContinuousBypassesLimitsAndBudget(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/continuous", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 19999) AS n`), streamID); err != nil {
		t.Fatal(err)
	}
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
SELECT pg_sleep(CASE WHEN $2::bigint = 0 THEN 3.2 ELSE 0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	db.mu.Lock()
	db.batchCh = []chan *LogEntry{make(chan *LogEntry, 2)}
	db.batchCh[0] <- &LogEntry{}
	db.batchCh[0] <- &LogEntry{}
	db.mu.Unlock()
	db.gapScanPermit <- struct{}{}
	defer func() { <-db.gapScanPermit }()
	ls.gapCh = make(chan gap, 1)
	if err := db.selectStreamGapsMode(ctx, ls, nil, false, nil); !errors.Is(err, errGapScanDeferred) {
		t.Fatalf("shared scan with full queue: %v, want deferral", err)
	}
	ls.gapCh = make(chan gap, 1)
	ls.SetGapScanContinuous(true)
	if err := db.selectStreamGapsMode(ctx, ls, nil, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := ls.GapScanIndex.Load(); got != 20_000 {
		t.Fatalf("continuous scan reached %d, want 20000 after the 3-second start budget", got)
	}
	if got := len(db.gapScanPermit); got != 1 {
		t.Fatalf("shared scan permit count = %d, want 1 still held", got)
	}
}

func TestGapScanContinuousStopsQueuedGapsOnDisable(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/stop-continuous", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2, 4}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.SetGapScanContinuous(true)
	gapCh := make(chan gap, 1)
	done := make(chan error, 1)
	go func() {
		cursor := int64(0)
		_, _, err := db.sendGapWindow(ctx, ls, gapCh, 0, 4, &cursor, true, true)
		done <- err
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for ls.Backfill.Load() < 2 {
		select {
		case <-ticker.C:
		case err := <-done:
			t.Fatalf("scan stopped before queue filled: %v", err)
		case <-deadline.C:
			t.Fatal("scan did not reach full gap queue")
		}
	}
	ls.SetGapScanContinuous(false)
	select {
	case err := <-done:
		if !errors.Is(err, errGapScanDeferred) {
			t.Fatalf("scan error = %v, want deferral on disable", err)
		}
	case <-deadline.C:
		t.Fatal("full gap queue did not wake on disable")
	}
	if got := ls.Backfill.Load(); got != 1 {
		t.Fatalf("Backfill = %d, want only the queued gap", got)
	}
}

func TestGapScanContinuousWakesScheduledScan(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/wake-continuous", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1, 2}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	scanCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go db.rescanGaps(scanCtx, ls, time.Now().Add(time.Hour), &wg)
	defer func() { cancel(); wg.Wait() }()
	ls.SetGapScanContinuous(true)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for ls.GapScanIndex.Load() < 3 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("continuous scan did not wake before the scheduled cold scan")
		}
	}
}
