package certstream

import (
	"context"
	"errors"
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestPgDB_GapCountCompleteness(t *testing.T) {
	ctx, db, _ := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/gap-count", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1, 3, 5}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		start, end int64
		count      int64
		complete   bool
	}{
		{name: "dense", start: 0, end: 1, count: 2, complete: true},
		{name: "leading gap", start: 2, end: 3, count: 1},
		{name: "internal gap", start: 1, end: 3, count: 2},
		{name: "trailing gap", start: 3, end: 4, count: 1},
		{name: "empty", start: 6, end: 8, count: 0},
		{name: "single entry", start: 5, end: 5, count: 1, complete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var count int64
			if err := db.QueryRow(ctx, db.stmtSelectGapCount, streamID, tc.start, tc.end).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != tc.count {
				t.Fatalf("count(%d..%d) = %d, want %d", tc.start, tc.end, count, tc.count)
			}
			complete, err := db.completeGapRange(ctx, streamID, tc.start, tc.end)
			if err != nil {
				t.Fatal(err)
			}
			if complete != tc.complete {
				t.Fatalf("complete(%d..%d) = %t, want %t", tc.start, tc.end, complete, tc.complete)
			}
		})
	}
}

func TestGapScanColdCountSkipsDenseRange(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/gap-count-dense"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 999999) AS n`), streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{1_999_999}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`VACUUM (ANALYZE) CERTDB_entry`)); err != nil {
		t.Fatal(err)
	}

	// A linear scan needs 100 slow 10k reads; the probe skips 99 of them.
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint < 1000000 THEN 0.1 ELSE 0.0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
		gapCh:       make(chan gap, 128),
	}
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor < gapProbeSize-1 {
		t.Fatalf("cold cursor = %d, want at least %d", cursor, gapProbeSize-1)
	}
}

func TestGapScanColdCountFindsGap(t *testing.T) {
	for _, tc := range []struct {
		name         string
		missingIndex int64
	}{
		{name: "first_window", missingIndex: 5},
		{name: "middle", missingIndex: 300_005},
		{name: "near_end", missingIndex: 999_995},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db, cs := setupSelectGapsDB(t)
			var operatorID, streamID int32
			if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
				t.Fatal(err)
			}
			url := "https://example.test/gap-count-" + tc.name
			if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 999999) AS n WHERE n <> $2`), streamID, tc.missingIndex); err != nil {
				t.Fatal(err)
			}
			if err := insertEntries(ctx, db, streamID, []int64{1_999_999}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, db.Pfx(`VACUUM (ANALYZE) CERTDB_entry`)); err != nil {
				t.Fatal(err)
			}

			// Each cold window takes 100ms. The middle and end gaps require
			// narrowing the incomplete range to finish within one 3s pass.
			db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint < 1000000 THEN 0.1 ELSE 0.0 END)
)
SELECT e.logindex FROM CERTDB_entry e CROSS JOIN pause
WHERE e.stream = $1 AND e.logindex BETWEEN $2 AND $3 ORDER BY e.logindex`)
			ls := &LogStream{
				LogOperator: &LogOperator{CertStream: cs},
				Id:          streamID,
				log:         &loglist3.Log{URL: url},
				gapCh:       make(chan gap, 128),
			}
			if err := db.selectStreamGaps(ctx, ls); err != nil {
				t.Fatal(err)
			}
			var cold []gap
			for _, g := range collectGaps(ls.gapCh) {
				if g.start < gapProbeSize {
					cold = append(cold, g)
				}
			}
			want := []gap{{start: tc.missingIndex, end: tc.missingIndex}}
			if !gapsEqual(cold, want) {
				t.Fatalf("cold gaps = %v, want %v", cold, want)
			}
			var cursor int64
			if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
				t.Fatal(err)
			}
			if cursor != tc.missingIndex {
				t.Fatalf("cold cursor = %d, want %d", cursor, tc.missingIndex)
			}
		})
	}
}

func TestGapScanColdCountFallsBackForGapAndTimeout(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/gap-count-fallback"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 10005) AS n
WHERE n NOT IN (10002, 10004)`), streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{1_999_999}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
	}
	check := func(t *testing.T) {
		t.Helper()
		ls.gapCh = make(chan gap, 128)
		if err := db.selectStreamGaps(ctx, ls); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		var cold []gap
		for _, g := range collectGaps(ls.gapCh) {
			if g.start < gapProbeSize {
				cold = append(cold, g)
			}
		}
		want := []gap{{start: 10002, end: 10002}, {start: 10004, end: 10004}, {start: 10006, end: 19999}}
		if !gapsEqual(cold, want) {
			t.Fatalf("cold gaps = %v, want %v", cold, want)
		}
		var cursor int64
		if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if cursor != 10002 {
			t.Fatalf("cold cursor = %d, want 10002", cursor)
		}
	}
	t.Run("incomplete", check)
	if _, err := db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream SET backfill_logindex = 0 WHERE id = $1`), streamID); err != nil {
		t.Fatal(err)
	}
	db.stmtSelectGapCount = db.Pfx(`WITH pause AS MATERIALIZED (SELECT pg_sleep(1))
SELECT count(*) FROM CERTDB_entry CROSS JOIN pause
WHERE stream = $1 AND logindex BETWEEN $2 AND $3`)
	t.Run("probe timeout", check)
}
