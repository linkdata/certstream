package certstream_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// BenchmarkIngestBatchOverlap measures ingest with expired history and an overlap.
//
// Each iteration ingests the same new certificate in a rolled-back transaction.
// Targets include matching and opposite precertificate types. Unrelated names
// keep the fixture selective, and vacuum makes history all-visible.
// An untimed full-ingest EXPLAIN reports shared buffer accesses for each sample.
// Run with -benchtime=50x -count=6 when comparing SQL revisions.
func BenchmarkIngestBatchOverlap(b *testing.B) {
	ctx, conn, streamID := setupIngestBatchTest(b)
	var issuerID, subjectID int32
	for _, ident := range []struct {
		organization string
		id           *int32
	}{
		{"Issuer Org", &issuerID},
		{"Subject Org", &subjectID},
	} {
		if err := conn.QueryRow(ctx, `
INSERT INTO CERTDB_ident (organization, province, country)
VALUES ($1, 'CA', 'US') RETURNING id`, ident.organization).Scan(ident.id); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := conn.Exec(ctx, `
INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
SELECT timestamp '2020-01-01' + g * interval '1 minute', timestamp '2021-01-01',
       timestamp '2020-01-01', 'expired.example.com', $1, $2,
       decode(lpad(to_hex(g), 64, '0'), 'hex'), false
FROM generate_series(1, 50000) AS g`, subjectID, issuerID); err != nil {
		b.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
SELECT timestamp '2020-01-01', timestamp '2021-01-01', timestamp '2020-01-01',
       'filler-' || g || '.example.com', $1, $2,
       decode(lpad(to_hex(100000 + g), 64, '0'), 'hex'), false
FROM generate_series(1, 100000) AS g`, subjectID, issuerID); err != nil {
		b.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
VALUES ('2020-01-01', '2025-01-01', '2020-01-01', 'overlap.example.com', $1, $2,
        decode(lpad(to_hex(50001), 64, '0'), 'hex'), false)`, subjectID, issuerID); err != nil {
		b.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "VACUUM (ANALYZE) CERTDB_cert"); err != nil {
		b.Fatal(err)
	}

	for i, tc := range []struct {
		name, commonName string
		precert          bool
	}{
		{"expired_history", "expired.example.com", false},
		{"ordinary_overlap", "overlap.example.com", false},
		{"opposite_precert_history", "expired.example.com", true},
	} {
		row := ingestRowWithSHA(streamID, int64(50002+i), tc.commonName,
			time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC), fmt.Sprintf("%064x", 50002+i))
		row["commonname"] = tc.commonName
		row["precert"] = tc.precert
		row["notbefore"] = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		row["notafter"] = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		payload, err := json.Marshal([]map[string]any{row})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
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
			b.StopTimer()
			tx, err := conn.Begin(ctx)
			if err != nil {
				b.Fatal(err)
			}
			var planJSON []byte
			if err = tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT CERTDB_ingest_batch($1::jsonb)", string(payload)).Scan(&planJSON); err != nil {
				b.Fatal(err)
			}
			if err = tx.Rollback(ctx); err != nil {
				b.Fatal(err)
			}
			var plans []struct {
				Plan struct {
					Hits  int64 `json:"Shared Hit Blocks"`
					Reads int64 `json:"Shared Read Blocks"`
				} `json:"Plan"`
			}
			if err = json.Unmarshal(planJSON, &plans); err != nil {
				b.Fatal(err)
			}
			if len(plans) != 1 || plans[0].Plan.Hits+plans[0].Plan.Reads == 0 {
				b.Fatal("EXPLAIN omitted database buffer usage")
			}
			b.ReportMetric(float64(plans[0].Plan.Hits+plans[0].Plan.Reads), "db_buffers/op")
		})
	}
}
