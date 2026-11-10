package certstream

import (
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

func TestGapScanQueuesGapsAscending(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		indices []int64
	}{
		{"cold before recent", []int64{0, 2, 4, 1_000_010, 1_000_012, 1_000_020}},
		{"recent windows", []int64{0, 2, 10_000, 10_002, 20_000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var streamID int32
			if err := insertStream(ctx, db, "https://example.test/gap-order-"+tc.name, operatorID, &streamID); err != nil {
				t.Fatal(err)
			}
			if err := insertEntries(ctx, db, streamID, tc.indices); err != nil {
				t.Fatal(err)
			}
			ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, gapCh: make(chan gap, 32)}
			if err := db.selectStreamGaps(ctx, ls); err != nil {
				t.Fatal(err)
			}
			gaps := collectGaps(ls.gapCh)
			if len(gaps) < 2 || gaps[0].start != 1 {
				t.Fatalf("gaps = %v, want ascending from index 1", gaps)
			}
			previousEnd := int64(-1)
			for _, g := range gaps {
				if g.start <= previousEnd {
					t.Fatalf("gaps out of order: %v", gaps)
				}
				previousEnd = g.end
			}
		})
	}
}

func TestGapScanReportsSuppressedRecentPass(t *testing.T) {
	ctx, db, ls := setupGapScanStream(t, 0, 2, 4)
	if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
		t.Fatal(err)
	}
	cold := coldScanState{next: 1, end: 4, cursor: 1, cursorBlocked: true}
	ls.gapCh = make(chan gap, 2)
	if err := db.selectStreamGapsMode(ctx, ls, &cold, true, nil); err != nil {
		t.Fatal(err)
	}
	if cold.recentComplete {
		t.Fatal("recent scan reported after unfinished cold sweep suppressed it")
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{1, 1}, {3, 3}}) {
		t.Fatalf("cold gaps = %v, want 1 and 3", got)
	}
	ls.gapCh = make(chan gap, 2)
	if err := db.selectStreamGapsMode(ctx, ls, &cold, true, nil); err != nil {
		t.Fatal(err)
	}
	if !cold.recentComplete {
		t.Fatal("completed recent scan was not reported")
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{1, 1}, {3, 3}}) {
		t.Fatalf("recent gaps = %v, want 1 and 3", got)
	}
	db.stmtSelectGapWindow = db.Pfx(`SELECT logindex FROM CERTDB_missing_entry`)
	ls.gapCh = make(chan gap, 2)
	if err := db.selectStreamGapsMode(ctx, ls, &cold, true, nil); err == nil {
		t.Fatal("failed recent query returned no error")
	}
	if cold.recentComplete {
		t.Fatal("failed recent query reported a completed scan")
	}
}

func TestGapScanHotTimeoutResumesAfterQueuedGap(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/hot-timeout-resume", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2, 4, 6, 10}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`CREATE TABLE CERTDB_test_scan_starts (
  id bigint GENERATED ALWAYS AS IDENTITY,
  start_index bigint NOT NULL
)`)); err != nil {
		t.Fatal(err)
	}
	db.stmtSelectGapWindow = db.Pfx(`WITH mark AS (
  INSERT INTO CERTDB_test_scan_starts (start_index) VALUES ($2::bigint) RETURNING start_index
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN mark
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, gapCh: make(chan gap, 1)}
	if err := db.selectStreamGaps(ctx, ls); !errors.Is(err, errGapChannelFull) {
		t.Fatalf("scan error = %v, want full cold channel after hot timeout", err)
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{1, 1}}) {
		t.Fatalf("queued gaps = %v, want only first gap", got)
	}
	rows, err := db.Query(ctx, db.Pfx(`SELECT start_index FROM CERTDB_test_scan_starts ORDER BY id`))
	if err != nil {
		t.Fatal(err)
	}
	var starts []int64
	for rows.Next() {
		var start int64
		if err := rows.Scan(&start); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		starts = append(starts, start)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(starts) != 2 || starts[0] != 0 || starts[1] != 2 {
		t.Fatalf("scan starts = %v, want [0 2]", starts)
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

func TestGapScanColdProgressBeforeRecentTail(t *testing.T) {
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
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.gapCh = make(chan gap, 128)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	gaps := collectGaps(ls.gapCh)
	if len(gaps) < 3 || !gapsEqual(gaps[:3], []gap{{2, 2}, {4, 9}, {11, 9983}}) {
		t.Fatalf("cold gaps before recent tail = %v", gaps)
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
