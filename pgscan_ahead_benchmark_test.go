package certstream

import (
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
					found, _, err = db.sendGapWindow(ctx, ls, gapCh, gapWindowSize, 2*gapWindowSize-1, &cursor, false)
					if err != nil {
						b.Fatal(err)
					}
					if !found {
						b.Fatal("second gap not found")
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
