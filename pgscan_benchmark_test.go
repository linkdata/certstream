package certstream

import (
	"sync/atomic"
	"testing"
)

// BenchmarkGapScanSQL compares chunk costs and progress latency over a million indexes.
func BenchmarkGapScanSQL(b *testing.B) {
	const total int64 = 1_000_000
	ctx, db, _ := setupSelectGapsDB(b)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		b.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/gap-scan-benchmark", operatorID, &streamID); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`ALTER TABLE CERTDB_entry SET (autovacuum_enabled = false)`)); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 999999) AS n`), streamID); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`ANALYZE CERTDB_entry`)); err != nil {
		b.Fatal(err)
	}

	modes := []struct {
		name string
		step int64
	}{
		{"1m", total},
		{"500k", 500_000},
		{"250k", 250_000},
		{"100k", 100_000},
	}
	scan := func(b *testing.B, step int64, want []gap) {
		b.Helper()
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			var got []gap
			for start, size := int64(0), gapWindowSize; start < total; {
				end := min(total-1, start+size-1)
				gaps, err := db.storedGaps(ctx, streamID, start, end)
				if err != nil {
					b.Fatal(err)
				}
				got = append(got, gaps...)
				start, size = end+1, step
			}
			if !gapsEqual(got, want) {
				b.Fatalf("gaps = %v, want %v", got, want)
			}
		}
	}
	for _, mode := range modes {
		b.Run("unvacuumed_total_"+mode.name, func(b *testing.B) { scan(b, mode.step, nil) })
	}
	if _, err := db.Exec(ctx, db.Pfx(`VACUUM (ANALYZE) CERTDB_entry`)); err != nil {
		b.Fatal(err)
	}
	for _, mode := range modes {
		b.Run("vacuumed_total_"+mode.name, func(b *testing.B) { scan(b, mode.step, nil) })
		b.Run("first_progress_"+mode.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				end := min(total-1, gapWindowSize+mode.step-1)
				gaps, err := db.storedGaps(ctx, streamID, gapWindowSize, end)
				if err != nil {
					b.Fatal(err)
				}
				if len(gaps) != 0 {
					b.Fatalf("unexpected gaps: %v", gaps)
				}
			}
		})
	}
	b.Run("streaming_progress_1m", func(b *testing.B) {
		var position atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			position.Store(gapWindowSize)
			gaps, err := db.storedGapsProgress(ctx, streamID, gapWindowSize, total-1, position.Store)
			if err != nil {
				b.Fatal(err)
			}
			if len(gaps) != 0 || position.Load() != total {
				b.Fatalf("gaps = %v, progress = %d, want no gaps and %d", gaps, position.Load(), total)
			}
		}
	})
	b.Run("first_visible_streamed_1m", func(b *testing.B) {
		var position atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			observed := false
			gaps, err := db.storedGapsProgress(ctx, streamID, gapWindowSize, total-1, func(index int64) {
				position.Store(index)
				if !observed {
					// Measure only work before the first visible update.
					b.StopTimer()
					observed = true
				}
			})
			if err != nil {
				b.Fatal(err)
			}
			if len(gaps) != 0 || !observed || position.Load() != total {
				b.Fatalf("gaps = %v, observed = %t, progress = %d", gaps, observed, position.Load())
			}
			b.StartTimer()
		}
	})
	const missingIndex = total - 5
	if tag, err := db.Exec(ctx, db.Pfx(`DELETE FROM CERTDB_entry WHERE stream = $1 AND logindex = $2`), streamID, missingIndex); err != nil {
		b.Fatal(err)
	} else if tag.RowsAffected() != 1 {
		b.Fatalf("deleted %d entries, want 1", tag.RowsAffected())
	}
	for _, mode := range modes {
		b.Run("sparse_total_"+mode.name, func(b *testing.B) {
			scan(b, mode.step, []gap{{start: missingIndex, end: missingIndex}})
		})
	}
}
