package certstream

import "testing"

// BenchmarkGapScanContinuousParallel compares shared and independent scan admission.
func BenchmarkGapScanContinuousParallel(b *testing.B) {
	ctx, db, cs := setupSelectGapsDB(b)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		b.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/continuous-benchmark", operatorID, &streamID); err != nil {
		b.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0}); err != nil {
		b.Fatal(err)
	}
	addGapQuerySleep(b, db, "0.02")
	for _, mode := range []struct {
		name       string
		continuous bool
	}{
		{name: "shared"},
		{name: "continuous", continuous: true},
	} {
		b.Run(mode.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, gapCh: make(chan gap, 1)}
					ls.SetGapScanContinuous(mode.continuous)
					if err := db.selectStreamGapsMode(ctx, ls, nil, false, nil); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}
