package certstream

import (
	"context"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestGapScanProgressRemainsAheadOfCommittedCursor(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/gap-scan-progress", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2, 4}); err != nil {
		t.Fatal(err)
	}
	ls, _ := newTileTestStream(t, 5)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(4)
	ls.gapCh = make(chan gap, 2)
	cold := coldScanState{next: -1, end: -1}
	if err := db.selectStreamGapsMode(ctx, ls, &cold, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{1, 1}, {3, 3}}) {
		t.Fatalf("discovered gaps = %v, want 1 and 3", got)
	}
	if got := ls.GapScanIndex.Load(); got != 5 {
		t.Fatalf("GapScanIndex = %d, want next scan index 5", got)
	}

	check := func(wantCursor int64, firstStored, secondStored bool) {
		t.Helper()
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
		var first, second bool
		if err := db.QueryRow(ctx, db.Pfx(`SELECT EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 3)`), streamID).Scan(&first, &second); err != nil {
			t.Fatal(err)
		}
		if first != firstStored || second != secondStored {
			t.Fatalf("stored holes = (%t, %t), want (%t, %t)", first, second, firstStored, secondStored)
		}
	}
	check(1, false, false)
	for _, tc := range []struct {
		index      int64
		wantCursor int64
		first      bool
		second     bool
	}{
		{1, 2, true, false},
		{3, 4, true, true},
	} {
		ls.gapCh = make(chan gap, 1)
		ls.gapCh <- gap{start: tc.index, end: tc.index}
		close(ls.gapCh)
		if err := db.backfillGapsWithFetcherMode(ctx, ls, ls.getGapEntries, nil, false); err != nil {
			t.Fatal(err)
		}
		check(tc.wantCursor, tc.first, tc.second)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
}

func TestRecentGapLowersCursorBeforeRepairCommits(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/recent-cursor-race", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 10005) AS n WHERE n <> 2`), streamID); err != nil {
		t.Fatal(err)
	}
	ls, _ := newTileTestStream(t, 256)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(10005)
	if err := db.backfillSetGapStartIndex(ctx, ls, 10005); err != nil {
		t.Fatal(err)
	}
	// Hold the second recent window until the repair commits index 2.
	holder, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	key := int64(streamID)
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			if _, err := holder.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key); err != nil {
				t.Errorf("unlock scanner: %v", err)
			}
		}
	}()
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_advisory_xact_lock(CASE WHEN $2::bigint = 10000 THEN $1::bigint ELSE -1 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	cold := coldScanState{next: -1, end: -1}
	done := make(chan error, 1)
	go func() { done <- db.scanAndBackfillGapsMode(ctx, ls, ls.getGapEntries, false, &cold, true, nil) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	committed := false
	for !committed {
		select {
		case <-ticker.C:
			if err := db.QueryRow(ctx, db.Pfx(`SELECT EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 2)`), streamID).Scan(&committed); err != nil {
				t.Fatal(err)
			}
		case err := <-done:
			t.Fatalf("scan stopped before repair committed: %v", err)
		case <-deadline.C:
			t.Fatal("repair did not commit while recent scan was paused")
		}
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock($1)`, key); err != nil {
		t.Fatal(err)
	}
	locked = false
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 3 {
		t.Fatalf("backfill_logindex = %d, want 3 after committed recent gap", cursor)
	}
}
