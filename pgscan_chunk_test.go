package certstream

import (
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestGapScanColdChunk(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/gap-chunk"
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

	// A crawl of 10k cold windows exceeds the cold-start budget; one broad read fits.
	db.stmtSelectGapWindow = db.Pfx(`WITH pause AS MATERIALIZED (
  SELECT pg_sleep(CASE WHEN $2::bigint >= 10000 AND $3::bigint - $2::bigint < 100000 THEN 0.1 ELSE 0.0 END)
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
	if cursor < 999_999 {
		t.Fatalf("cold cursor = %d, want at least 999999", cursor)
	}

	if _, err := db.Exec(ctx, db.Pfx(`DELETE FROM CERTDB_entry WHERE stream = $1 AND logindex = 999995`), streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream SET backfill_logindex = 0 WHERE id = $1`), streamID); err != nil {
		t.Fatal(err)
	}
	ls.gapCh = make(chan gap, 128)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	var cold []gap
	for _, g := range collectGaps(ls.gapCh) {
		if g.start < gapRecentLookback {
			cold = append(cold, g)
		}
	}
	if want := []gap{{start: 999_995, end: 999_995}}; !gapsEqual(cold, want) {
		t.Fatalf("cold gaps = %v, want %v", cold, want)
	}
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 999_995 {
		t.Fatalf("cold cursor = %d, want 999995", cursor)
	}
}
