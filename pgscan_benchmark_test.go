package certstream

import (
	"database/sql"
	"testing"
)

// BenchmarkGapScanSQL compares indexed PostgreSQL work for the full suffix and bounded window queries.
func BenchmarkGapScanSQL(b *testing.B) {
	ctx, db, _ := setupSelectGapsDB(b)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		b.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/benchmark", operatorID, &streamID); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream) SELECT n + 1000, n, $1 FROM generate_series(1, 200000) AS n`), streamID); err != nil {
		b.Fatal(err)
	}
	b.Run("full_suffix", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			var start, end sql.NullInt64
			if err := db.QueryRow(ctx, db.Pfx(SelectFindGap), streamID, 1, 200000).Scan(&start, &end); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("bounded_window", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := db.storedGaps(ctx, streamID, 1, gapWindowSize); err != nil {
				b.Fatal(err)
			}
		}
	})
}
