package certstream

import (
	"context"
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"
)

// BenchmarkGapScanAhead measures how many separated cold gaps one pass reports.
func BenchmarkGapScanAhead(b *testing.B) {
	ctx, db, cs := setupSelectGapsDB(b)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		b.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/gap-scan-ahead-benchmark", operatorID, &streamID); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 19999) AS n
WHERE n NOT IN (5, 10005)`), streamID); err != nil {
		b.Fatal(err)
	}
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: "https://example.test/gap-scan-ahead-benchmark"},
	}

	// The first window is common to both paths. A stop-first pass reports
	// only its gap; a scan-ahead pass reads the following window as well.
	for _, tc := range []struct {
		name string
		want int
	}{
		{name: "stop_after_first_gap", want: 1},
		{name: "scan_ahead", want: 2},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				ls.Backfill.Store(0)
				gapCh := make(chan gap, 2)
				cursor := int64(0)
				found, _, err := db.sendGapWindow(ctx, ls, gapCh, 0, gapWindowSize-1, &cursor, false)
				if err != nil {
					b.Fatal(err)
				}
				if !found {
					b.Fatal("first gap not found")
				}
				if tc.want == 2 {
					scanPos := gapWindowSize
					persist := false
					if err := db.sendColdGapRange(ctx, ls, gapCh, 2*gapWindowSize-1, &scanPos, &cursor, &persist); err != nil {
						b.Fatal(err)
					}
				}
				if len(gapCh) != tc.want {
					b.Fatalf("reported %d gaps, want %d", len(gapCh), tc.want)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*tc.want), "ns/gap")
			b.ReportMetric(float64(tc.want), "gaps/pass")
		})
	}
}

// BenchmarkGapScanDenseGaps compares repeated counts with linear reads after a gap.
func BenchmarkGapScanDenseGaps(b *testing.B) {
	ctx, db, cs := setupSelectGapsDB(b)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		b.Fatal(err)
	}
	const url = "https://example.test/gap-scan-dense-benchmark"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`ALTER TABLE CERTDB_entry SET (autovacuum_enabled = false)`)); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 999999) AS n
WHERE n % 50000 <> 25000`), streamID); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`ANALYZE CERTDB_entry`)); err != nil {
		b.Fatal(err)
	}
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
	}

	for _, tc := range []struct {
		name string
		old  bool
	}{
		{name: "repeated_counts", old: true},
		{name: "linear_after_gap"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			run := func() error {
				ls.Backfill.Store(0)
				gapCh := make(chan gap, 20)
				cursor := int64(0)
				_, _, err := db.sendGapWindow(ctx, ls, gapCh, 0, gapWindowSize-1, &cursor, false)
				if err != nil {
					return err
				}
				scanPos := gapWindowSize
				if tc.old {
					err = benchmarkRepeatedGapCounts(ctx, db, ls, gapCh, gapProbeSize-1, &scanPos, &cursor)
				} else {
					persist := false
					err = db.sendColdGapRange(ctx, ls, gapCh, gapProbeSize-1, &scanPos, &cursor, &persist)
				}
				if err == nil && len(gapCh) != 20 {
					b.Fatalf("reported %d gaps, want 20", len(gapCh))
				}
				return err
			}
			if err := run(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := run(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkRepeatedGapCounts(ctx context.Context, db *PgDB, ls *LogStream, gapCh chan gap, end int64, scanPos, cursor *int64) (err error) {
	incomplete := false
	hi := end
	for *scanPos <= end {
		checkEnd := end
		if incomplete {
			checkEnd = *scanPos + (hi-*scanPos)/2
		}
		if checkEnd-*scanPos+1 <= gapWindowSize {
			checkEnd = min(end, *scanPos+gapWindowSize-1)
			_, *scanPos, err = db.sendGapWindow(ctx, ls, gapCh, *scanPos, checkEnd, cursor, false)
			if err != nil {
				return
			}
			incomplete = false
			hi = end
			continue
		}
		var complete bool
		complete, err = db.completeGapRange(ctx, ls.Id, *scanPos, checkEnd)
		if err != nil {
			return
		}
		if !complete {
			incomplete = true
			hi = checkEnd
			continue
		}
		*scanPos = checkEnd + 1
	}
	return
}
