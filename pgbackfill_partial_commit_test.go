package certstream

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestGapScanPartialFetchCommitsPrefixAndResumes(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/partial-gap-commit", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2, 4}); err != nil {
		t.Fatal(err)
	}
	ls, transport := newTileTestStream(t, 5)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(4)
	cold := coldScanState{next: -1, end: -1}
	var pending bool

	partialCalls := 0
	partial := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		partialCalls++
		if start != 1 || end != 3 {
			t.Fatalf("partial fetch = %d..%d, want 1..3", start, end)
		}
		var wanted bool
		for index := start; index < 2; index++ {
			wanted = handle(ctx, time.Now(), ls.makeTileLogEntry(index, transport.entries[index], true)) || wanted
			remaining.Add(-1)
		}
		return 2, wanted
	}
	if err := db.scanAndBackfillGapsMode(ctx, ls, partial, false, &cold, false, &pending); !errors.Is(err, errGapIncomplete) {
		t.Fatalf("partial scan error = %v, want %v", err, errGapIncomplete)
	}
	if partialCalls != 1 {
		t.Fatalf("partial fetch calls = %d, want 1", partialCalls)
	}
	check := func(wantCursor int64, wantSecond bool) {
		t.Helper()
		var first, second bool
		if err := db.QueryRow(ctx, db.Pfx(`SELECT EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 3)`), streamID).Scan(&first, &second); err != nil {
			t.Fatal(err)
		}
		if !first || second != wantSecond {
			t.Fatalf("stored holes = (%t, %t), want (true, %t)", first, second, wantSecond)
		}
		var cursor int64
		if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if cursor != wantCursor {
			t.Fatalf("backfill_logindex = %d, want %d", cursor, wantCursor)
		}
		if got := ls.GapScanIndex.Load(); got != 5 {
			t.Fatalf("GapScanIndex = %d, want scanned position 5", got)
		}
		if cold.next != -1 || cold.end != -1 {
			t.Fatalf("cold scan state = %+v, want completed sweep", cold)
		}
		if got := ls.Backfill.Load(); got != 0 {
			t.Fatalf("Backfill = %d, want 0", got)
		}
	}
	check(3, false)
	if err := db.scanAndBackfillGapsMode(ctx, ls, ls.getGapEntries, false, &cold, false, &pending); err != nil {
		t.Fatal(err)
	}
	check(4, true)
}

func TestGapScanRetriesOldestGapInUnfinishedSweep(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/retry-oldest-gap", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 20005) AS n WHERE n <> 2`), streamID); err != nil {
		t.Fatal(err)
	}
	ls, _ := newTileTestStream(t, 256)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(20005)
	cold := coldScanState{next: -1, end: -1}
	var pending bool
	// A real slow first database read leaves the cold sweep unfinished.
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint = 0 THEN 3.2 ELSE 0.0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	failedFetch := func(_ context.Context, start, _ int64, _ bool, _ handleLogEntryFn, _ *atomic.Int64) (int64, bool) {
		return start, false
	}
	if err := db.scanAndBackfillGapsMode(ctx, ls, failedFetch, false, &cold, false, &pending); !errors.Is(err, errGapIncomplete) {
		t.Fatalf("first scan error = %v, want %v", err, errGapIncomplete)
	}
	if got := ls.GapScanIndex.Load(); got != 9984 {
		t.Fatalf("GapScanIndex = %d, want actual first scan progress 9984", got)
	}
	if cold.next != 2 || cold.end != 20005 || cold.cursorBlocked {
		t.Fatalf("cold state after failed fetch = %+v, want retry at 2", cold)
	}
	db.stmtSelectGapWindow = db.Pfx(selectGapWindow)
	if err := db.scanAndBackfillGapsMode(ctx, ls, ls.getGapEntries, false, &cold, false, &pending); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 3 {
		t.Fatalf("backfill_logindex = %d, want 3 after oldest gap commit", cursor)
	}
	if got := ls.GapScanIndex.Load(); got != 20006 {
		t.Fatalf("GapScanIndex = %d, want actual second scan progress 20006", got)
	}
}

func TestGapScanContinuesAfterOldestGapRetryFails(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/continue-after-failed-retry", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 20005) AS n WHERE n NOT IN (2, 15000)`), streamID); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.LastIndex.Store(20005)
	cold := coldScanState{next: -1, end: -1}
	var pending bool
	var fetched []int64
	failedFetch := func(_ context.Context, start, _ int64, _ bool, _ handleLogEntryFn, _ *atomic.Int64) (int64, bool) {
		fetched = append(fetched, start)
		return start, false
	}
	// The first two reads exhaust each pass's start budget.
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint IN (0, 2) THEN 3.2 ELSE 0.0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	for pass := range 2 {
		if err := db.scanAndBackfillGapsMode(ctx, ls, failedFetch, false, &cold, false, &pending); !errors.Is(err, errGapIncomplete) {
			t.Fatalf("pass %d error = %v, want %v", pass, err, errGapIncomplete)
		}
		if len(fetched) != pass+1 || fetched[pass] != 0 {
			t.Fatalf("fetch starts after pass %d = %v, want oldest tile twice", pass, fetched)
		}
	}
	if cold.next != 9984 || !cold.retryDone || cold.retryResume != 0 {
		t.Fatalf("cold state after failed retry = %+v, want resume at 9984", cold)
	}
	db.stmtSelectGapWindow = db.Pfx(selectGapWindow)
	if err := db.scanAndBackfillGapsMode(ctx, ls, failedFetch, false, &cold, false, &pending); !errors.Is(err, errGapIncomplete) {
		t.Fatalf("continued scan error = %v, want %v", err, errGapIncomplete)
	}
	if len(fetched) != 3 || fetched[2] != 14848 {
		t.Fatalf("fetch starts after continuing = %v, want later gap tile 14848", fetched)
	}
	if got := ls.GapScanIndex.Load(); got != 20006 {
		t.Fatalf("GapScanIndex = %d, want scan progress 20006", got)
	}
}

func TestGapScanKeepsOldestRetryOnQueueDeferral(t *testing.T) {
	db := &PgDB{batchCh: []chan *LogEntry{make(chan *LogEntry, 2)}}
	db.batchCh[0] <- &LogEntry{}
	db.batchCh[0] <- &LogEntry{}
	ls := &LogStream{LogOperator: &LogOperator{}}
	cold := coldScanState{next: 2, end: 20005, cursor: 2, retryResume: 9984}
	if err := db.scanAndBackfillGapsMode(t.Context(), ls, nil, false, &cold, false, nil); !errors.Is(err, errGapScanDeferred) {
		t.Fatalf("scan error = %v, want %v", err, errGapScanDeferred)
	}
	if cold.next != 2 || cold.retryResume != 9984 || cold.retryDone {
		t.Fatalf("cold state after queue deferral = %+v, want pending oldest retry", cold)
	}
}
