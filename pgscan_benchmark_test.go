package certstream

import "testing"

// BenchmarkGapScanSQL compares chunk sizes over one million indexes.
func BenchmarkGapScanSQL(b *testing.B) {
	const total int64 = 1_000_000
	const short int64 = 100_000
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
		size int64
	}{
		{"1m", total},
		{"100k", short},
		{"10k", gapWindowSize},
	}
	scan := func(b *testing.B, size int64, want []gap) {
		b.Helper()
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			var got []gap
			for start, length := int64(0), gapWindowSize; start < total; {
				end := min(total-1, start+length-1)
				gaps, err := db.storedGaps(ctx, streamID, start, end)
				if err != nil {
					b.Fatal(err)
				}
				got = append(got, gaps...)
				start, length = end+1, size
			}
			if !gapsEqual(got, want) {
				b.Fatalf("gaps = %v, want %v", got, want)
			}
		}
	}
	for _, mode := range modes {
		b.Run("unvacuumed_total_"+mode.name, func(b *testing.B) { scan(b, mode.size, nil) })
	}
	if _, err := db.Exec(ctx, db.Pfx(`VACUUM (ANALYZE) CERTDB_entry`)); err != nil {
		b.Fatal(err)
	}
	for _, mode := range modes {
		b.Run("vacuumed_total_"+mode.name, func(b *testing.B) { scan(b, mode.size, nil) })
	}
	b.Run("plain_query_1m", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			gaps, err := db.storedGaps(ctx, streamID, gapWindowSize, total-1)
			if err != nil || len(gaps) != 0 {
				b.Fatalf("gaps = %v, err = %v", gaps, err)
			}
		}
	})
	b.Run("plain_query_100k", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			gaps, err := db.storedGaps(ctx, streamID, gapWindowSize, gapWindowSize+short-1)
			if err != nil || len(gaps) != 0 {
				b.Fatalf("gaps = %v, err = %v", gaps, err)
			}
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
			scan(b, mode.size, []gap{{start: missingIndex, end: missingIndex}})
		})
	}
}
