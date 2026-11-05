package certstream

import (
	"errors"
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestGapScanAheadColdWindows(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/scan-ahead"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 20005) AS n WHERE n NOT IN (2, 15000)`), streamID); err != nil {
		t.Fatal(err)
	}

	// Exhaust the recent budget so the cold pass finds both missing indexes.
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint = 10006 THEN 4.0 ELSE 0.0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
		gapCh:       make(chan gap, 2),
	}
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{2, 2}, {15000, 15000}}) {
		t.Fatalf("queued gaps = %v, want gaps at 2 and 15000", got)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("backfill_logindex = %d, want first gap at 2", cursor)
	}
	if got := ls.GapScanIndex.Load(); got != 20_006 {
		t.Fatalf("GapScanIndex = %d, want 20006 after scanning past both gaps", got)
	}
	if got := ls.Backfill.Load(); got != 2 {
		t.Fatalf("Backfill = %d, want 2 queued entries", got)
	}
}

func TestGapScanAheadResumesAcrossPasses(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/scan-ahead-resume"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 30005) AS n WHERE n NOT IN (2, 15000)`), streamID); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
	}
	cold := coldScanState{next: -1, end: -1}
	check := func(capacity int, want []gap, wantErr error, wantCursor int64) {
		t.Helper()
		ls.gapCh = make(chan gap, capacity)
		var pending bool
		err := db.selectStreamGapsMode(ctx, ls, &cold, false, &pending)
		if !errors.Is(err, wantErr) {
			t.Fatalf("scan error = %v, want %v", err, wantErr)
		}
		if got := collectGaps(ls.gapCh); !gapsEqual(got, want) {
			t.Fatalf("queued gaps = %v, want %v", got, want)
		}
		var cursor int64
		if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if cursor != wantCursor {
			t.Fatalf("backfill_logindex = %d, want %d", cursor, wantCursor)
		}
		if !pending {
			t.Fatal("cold scan reported no pending gap")
		}
	}
	check(1, []gap{{2, 2}}, errGapChannelFull, 2)
	if cold.next != 15_000 || cold.end != 30_005 || !cold.cursorBlocked {
		t.Fatalf("cold state after deferral = %+v, want next 15000, end 30005", cold)
	}
	if got := ls.GapScanIndex.Load(); got != 15_000 {
		t.Fatalf("GapScanIndex after deferral = %d, want 15000", got)
	}
	if err := insertEntries(ctx, db, streamID, []int64{30_006}); err != nil {
		t.Fatal(err)
	}
	check(2, []gap{{15000, 15000}}, nil, 2)
	if cold.next != -1 || cold.end != -1 || cold.cursorBlocked {
		t.Fatalf("cold state after complete sweep = %+v, want reset", cold)
	}
	if got := ls.GapScanIndex.Load(); got != 30_006 {
		t.Fatalf("GapScanIndex after sweep = %d, want 30006", got)
	}
	// A sweep resuming at the durable cursor can advance after its gap is filled.
	if err := insertEntries(ctx, db, streamID, []int64{2}); err != nil {
		t.Fatal(err)
	}
	cold = coldScanState{next: 2, end: 30_006, cursorBlocked: true}
	check(2, []gap{{15000, 15000}}, nil, 15000)
	if got := ls.GapScanIndex.Load(); got != 30_007 {
		t.Fatalf("GapScanIndex after rescan = %d, want 30007", got)
	}
}

func TestGapScanAheadPersistsGapFreeProgressAcrossPasses(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/scan-ahead-dense-resume"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 20005) AS n`), streamID); err != nil {
		t.Fatal(err)
	}
	// The first read finishes after the start budget, leaving a gap-free sweep to resume.
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint = 0 THEN 3.2 ELSE 0.0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
	}
	cold := coldScanState{next: -1, end: -1}
	ls.gapCh = make(chan gap, 1)
	var pending bool
	if err := db.selectStreamGapsMode(ctx, ls, &cold, false, &pending); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 9_999 || cold.next != 10_000 || cold.cursorBlocked || !pending {
		t.Fatalf("first pass: cursor=%d, cold=%+v, pending=%t", cursor, cold, pending)
	}
	if got := ls.GapScanIndex.Load(); got != 10_000 {
		t.Fatalf("GapScanIndex after first pass = %d, want 10000", got)
	}

	db.stmtSelectGapWindow = db.Pfx(selectGapWindow)
	ls.gapCh = make(chan gap, 1)
	if err := db.selectStreamGapsMode(ctx, ls, &cold, false, &pending); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 20_005 || cold.next != -1 || cold.end != -1 || pending {
		t.Fatalf("second pass: cursor=%d, cold=%+v, pending=%t", cursor, cold, pending)
	}
	if got := ls.GapScanIndex.Load(); got != 20_006 {
		t.Fatalf("GapScanIndex after second pass = %d, want 20006", got)
	}
}

func TestSendGapWindowResumesAtUnqueuedGap(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/gap-window-resume"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1, 3, 5, 7, 8, 9}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
	}
	cursor := int64(0)
	gapCh := make(chan gap, 2)
	found, next, err := db.sendGapWindow(ctx, ls, gapCh, 0, 9, &cursor, true)
	if !found || !errors.Is(err, errGapChannelFull) || next != 6 {
		t.Fatalf("first window = (%t, %d, %v), want (true, 6, deferred)", found, next, err)
	}
	close(gapCh)
	if got := collectGaps(gapCh); !gapsEqual(got, []gap{{2, 2}, {4, 4}}) {
		t.Fatalf("first queued gaps = %v, want 2 and 4", got)
	}
	if cursor != 2 {
		t.Fatalf("cursor = %d, want first gap at 2", cursor)
	}
	gapCh = make(chan gap, 2)
	found, next, err = db.sendGapWindow(ctx, ls, gapCh, next, 9, &cursor, false)
	if !found || err != nil || next != 10 {
		t.Fatalf("resumed window = (%t, %d, %v), want (true, 10, nil)", found, next, err)
	}
	close(gapCh)
	if got := collectGaps(gapCh); !gapsEqual(got, []gap{{6, 6}}) {
		t.Fatalf("resumed gaps = %v, want only 6", got)
	}
}

func TestGapScanColdBoundaryGapRemainsPending(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/cold-boundary-gap"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 20000) AS n WHERE n <> 10000`), streamID); err != nil {
		t.Fatal(err)
	}
	// The recent pass covers 10001..20000, then exhausts its next-window budget.
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint = 1 THEN 4.0 ELSE 0.0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
		gapCh:       make(chan gap, 2),
	}
	var pending bool
	if err := db.selectStreamGapsMode(ctx, ls, nil, true, &pending); err != nil {
		t.Fatal(err)
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{10000, 10000}}) {
		t.Fatalf("queued gaps = %v, want boundary gap 10000", got)
	}
	if !pending {
		t.Fatal("boundary gap was not marked pending")
	}
}
