package certstream

import "testing"

// BenchmarkGapScanSQL compares query work over the same million-index range.
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
			for start := int64(0); start < gapProbeSize; start += gapWindowSize {
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
			gaps, err := db.storedGaps(ctx, streamID, 0, gapWindowSize-1)
			if err != nil {
				b.Fatal(err)
			}
			if len(gaps) != 0 {
				b.Fatalf("unexpected first-window gaps: %v", gaps)
			}
			complete, err := db.completeGapRange(ctx, streamID, gapWindowSize, gapProbeSize-1)
			if err != nil {
				b.Fatal(err)
			}
			if !complete {
				b.Fatal("dense range reported incomplete")
			}
		}
	}
	b.Run("unvacuumed_old_10k_windows", oldDense)
	b.Run("unvacuumed_new_count_probe", newDense)
	if _, err := db.Exec(ctx, db.Pfx(`VACUUM (ANALYZE) CERTDB_entry`)); err != nil {
		b.Fatal(err)
	}
	b.Run("vacuumed_old_10k_windows", oldDense)
	b.Run("vacuumed_new_count_probe", newDense)

	const missingIndex = gapProbeSize - 5
	tag, err := db.Exec(ctx, db.Pfx(`DELETE FROM CERTDB_entry WHERE stream = $1 AND logindex = $2`), streamID, missingIndex)
	if err != nil {
		b.Fatal(err)
	}
	if tag.RowsAffected() != 1 {
		b.Fatalf("deleted %d entries, want 1", tag.RowsAffected())
	}
	b.Run("sparse_old_10k_crawl", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			found := false
			for start := int64(0); start < gapProbeSize; start += gapWindowSize {
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
	b.Run("sparse_new_binary_queries", func(b *testing.B) {
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
			cursor, end := gapWindowSize, gapProbeSize-1
			hi := end
			incomplete := false
			found := false
			for cursor <= end {
				checkEnd := end
				if incomplete {
					checkEnd = cursor + (hi-cursor)/2
				}
				if checkEnd-cursor+1 <= gapWindowSize {
					checkEnd = min(end, cursor+gapWindowSize-1)
					gaps, err = db.storedGaps(ctx, streamID, cursor, checkEnd)
					if err != nil {
						b.Fatal(err)
					}
					if len(gaps) != 0 {
						if !gapsEqual(gaps, []gap{{start: missingIndex, end: missingIndex}}) {
							b.Fatalf("gaps = %v, want index %d", gaps, missingIndex)
						}
						found = true
						break
					}
					cursor = checkEnd + 1
					incomplete = false
					hi = end
					continue
				}
				complete, err := db.completeGapRange(ctx, streamID, cursor, checkEnd)
				if err != nil {
					b.Fatal(err)
				}
				if !complete {
					incomplete = true
					hi = checkEnd
					continue
				}
				cursor = checkEnd + 1
			}
			if !found {
				b.Fatal("near-end gap not found")
			}
		}
	})
}
