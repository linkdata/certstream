package certstream

import "testing"

// BenchmarkGapScanSQL compares ordered reads over one million index positions.
func BenchmarkGapScanSQL(b *testing.B) {
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

	oldDense := func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			for start := int64(0); start < gapColdChunkSize; start += gapWindowSize {
				gaps, err := db.storedGaps(ctx, streamID, start, start+gapWindowSize-1)
				if err != nil {
					b.Fatal(err)
				}
				if len(gaps) != 0 {
					b.Fatalf("unexpected gaps: %v", gaps)
				}
			}
		}
	}
	newDense := func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			for _, bounds := range [][2]int64{{0, gapWindowSize - 1}, {gapWindowSize, gapColdChunkSize - 1}} {
				gaps, err := db.storedGaps(ctx, streamID, bounds[0], bounds[1])
				if err != nil {
					b.Fatal(err)
				}
				if len(gaps) != 0 {
					b.Fatalf("unexpected gaps: %v", gaps)
				}
			}
		}
	}
	b.Run("unvacuumed_new_one_chunk", newDense)
	b.Run("unvacuumed_old_10k_windows", oldDense)
	if _, err := db.Exec(ctx, db.Pfx(`VACUUM (ANALYZE) CERTDB_entry`)); err != nil {
		b.Fatal(err)
	}
	b.Run("vacuumed_new_one_chunk", newDense)
	b.Run("vacuumed_old_10k_windows", oldDense)

	const missingIndex = gapColdChunkSize - 5
	if tag, err := db.Exec(ctx, db.Pfx(`DELETE FROM CERTDB_entry WHERE stream = $1 AND logindex = $2`), streamID, missingIndex); err != nil {
		b.Fatal(err)
	} else if tag.RowsAffected() != 1 {
		b.Fatalf("deleted %d entries, want 1", tag.RowsAffected())
	}
	b.Run("sparse_new_one_chunk", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			gaps, err := db.storedGaps(ctx, streamID, 0, gapWindowSize-1)
			if err != nil {
				b.Fatal(err)
			}
			if len(gaps) != 0 {
				b.Fatalf("unexpected first-window gaps: %v", gaps)
			}
			gaps, err = db.storedGaps(ctx, streamID, gapWindowSize, gapColdChunkSize-1)
			if err != nil {
				b.Fatal(err)
			}
			if !gapsEqual(gaps, []gap{{start: missingIndex, end: missingIndex}}) {
				b.Fatalf("gaps = %v, want index %d", gaps, missingIndex)
			}
		}
	})
	b.Run("sparse_old_10k_crawl", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			found := false
			for start := int64(0); start < gapColdChunkSize; start += gapWindowSize {
				gaps, err := db.storedGaps(ctx, streamID, start, start+gapWindowSize-1)
				if err != nil {
					b.Fatal(err)
				}
				if len(gaps) > 0 {
					if !gapsEqual(gaps, []gap{{start: missingIndex, end: missingIndex}}) {
						b.Fatalf("gaps = %v, want index %d", gaps, missingIndex)
					}
					found = true
					break
				}
			}
			if !found {
				b.Fatal("near-end gap not found")
			}
		}
	})
}
