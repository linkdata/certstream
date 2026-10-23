package certstream

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStoredGapsAtWindowBoundary(t *testing.T) {
	ctx, db, _ := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/boundary", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{9995, 9996, 10002, 10004}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		start, end int64
		want       []gap
	}{
		{9995, 9999, []gap{{9997, 9999}}},
		{10000, 10004, []gap{{10000, 10001}, {10003, 10003}}},
	} {
		got, err := db.storedGaps(ctx, streamID, tc.start, tc.end)
		if err != nil {
			t.Fatal(err)
		}
		if !gapsEqual(got, tc.want) {
			t.Fatalf("storedGaps(%d, %d) = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestGapScanWaitsForPermitWithoutUsingScanBudget(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/permit", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.gapCh = make(chan gap, 1)
	db.gapScanPermit <- struct{}{}
	held := true
	defer func() {
		if held {
			<-db.gapScanPermit
		}
	}()
	done := make(chan error, 1)
	go func() { done <- db.selectStreamGaps(ctx, ls) }()
	timer := time.NewTimer(11 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		t.Fatalf("scan returned while waiting for permit: %v", err)
	case <-timer.C:
	}
	<-db.gapScanPermit
	held = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not run after permit released")
	}
}

func TestGapScanLeavesNewStreamPrefixToReverseBackfill(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/reverse-prefix", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{2_000_000, 2_000_001}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.gapCh = make(chan gap, 2)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if got := collectGaps(ls.gapCh); len(got) != 0 {
		t.Fatalf("reverse-owned prefix reported as gaps: %v", got)
	}
}

func TestGapScanColdProgressAfterHotTimeout(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/hot-timeout", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1, 3, 10, 1_000_010}); err != nil {
		t.Fatal(err)
	}
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
		SELECT pg_sleep(CASE WHEN $2::bigint >= 900000 THEN 3.0 ELSE 0.0 END)
	) SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
	WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.gapCh = make(chan gap, 8)
	err := db.selectStreamGaps(ctx, ls)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hot query error = %v, want deadline", err)
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{2, 2}, {4, 9}, {11, 9999}}) {
		t.Fatalf("cold gaps after hot timeout = %v", got)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil || cursor != 2 {
		t.Fatalf("cold cursor = %d, err = %v, want 2", cursor, err)
	}
}

func TestGapScanFindsRecentHoleBelowCursor(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/cursor", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1, 3, 4}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.gapCh = make(chan gap, 4)
	if err := db.backfillSetGapStartIndex(ctx, ls, 4); err != nil {
		t.Fatal(err)
	}
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{2, 2}}) {
		t.Fatalf("gaps below cursor = %v, want [{2 2}]", got)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil || cursor != 2 {
		t.Fatalf("cursor after recent gap = %d, err = %v, want 2", cursor, err)
	}
}

func TestGapScanDefersAboveHalfQueue(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/busy", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.gapCh = make(chan gap, 1)
	db.mu.Lock()
	db.batchCh = []chan *LogEntry{make(chan *LogEntry, 2)}
	db.batchCh[0] <- &LogEntry{}
	db.batchCh[0] <- &LogEntry{}
	db.mu.Unlock()
	if err := db.selectStreamGaps(ctx, ls); !errors.Is(err, errGapScanDeferred) {
		t.Fatalf("scan error = %v, want deferred", err)
	}
	if got := collectGaps(ls.gapCh); len(got) != 0 {
		t.Fatalf("gaps while queue busy = %v", got)
	}
}
