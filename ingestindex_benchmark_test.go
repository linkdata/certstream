package certstream_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// BenchmarkIngestBatchIndexes measures complete database ingest batches.
//
// Each batch contains 1,000 new certificates, domain names, and stream entries.
// Each sub-benchmark uses its own database seeded with 100,000 domain names.
// Run with -benchtime=2x -count=6 for a bounded comparison.
func BenchmarkIngestBatchIndexes(b *testing.B) {
	for _, withTrigram := range []bool{false, true} {
		name := "without_trigram"
		if withTrigram {
			name = "with_trigram"
		}
		ctx, conn, streamID := setupIngestBenchmark(b, withTrigram)
		rows := make([]map[string]any, 1000)
		for i := range rows {
			rows[i] = ingestRowWithSHA(streamID, int64(i+1),
				fmt.Sprintf("node%d.example.com", i+1),
				time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
				fmt.Sprintf("%064x", i+1))
		}
		payload, err := json.Marshal(rows)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tx, err := conn.Begin(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = tx.Exec(ctx, "SELECT CERTDB_ingest_batch($1::jsonb)", string(payload)); err != nil {
					b.Fatal(err)
				}
				if err = tx.Rollback(ctx); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func setupIngestBenchmark(b *testing.B, withTrigram bool) (ctx context.Context, conn *pgx.Conn, streamID int32) {
	b.Helper()
	ctx, conn, streamID = setupIngestBatchTest(b)
	_, err := conn.Exec(ctx, `
SET synchronous_commit = off;
INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
VALUES ('2024-01-01', '2025-01-01', '2024-01-01', 'seed', 1, 1, decode(repeat('0', 64), 'hex'), false);
INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
SELECT c.id, false, 0, 'seed' || g || '.example', 'com'
FROM CERTDB_cert c CROSS JOIN generate_series(1, 100000) AS g
WHERE c.commonname = 'seed';
`)
	if err != nil {
		b.Fatal(err)
	}
	if withTrigram {
		if _, err = conn.Exec(ctx, `
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX certdb_domain_domain_tri_idx ON certdb_domain USING gin (domain gin_trgm_ops) WITH (fastupdate = off);
`); err != nil {
			b.Fatal(err)
		}
	}
	return
}
