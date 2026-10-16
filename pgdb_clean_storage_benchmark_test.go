package certstream

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// BenchmarkPgDB_DeleteCertificatesStorage measures complete cleanup batches,
// including foreign-key cascades, with IDs and expiry dates scattered across
// the heap. The ID permutation models production's poor ID-to-storage correlation.
// Transactions roll back so each query repeatedly deletes its own same batch.
// The cold_shared_buffers cases evict PostgreSQL buffers before each query;
// operating-system caches remain warm. These are not cold-disk measurements.
func BenchmarkPgDB_DeleteCertificatesStorage(b *testing.B) {
	ctx, db, _, _, identID := cleanTestFixture(b)
	cutoff := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	const batchSize = 1000
	for _, table := range []string{"cert", "domain", "ipaddress", "email", "uri"} {
		if _, err := db.Exec(ctx, db.Pfx("ALTER TABLE CERTDB_"+table+" SET (autovacuum_enabled = false)")); err != nil {
			b.Fatalf("disable autovacuum: %v", err)
		}
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_cert
    (id, notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
OVERRIDING SYSTEM VALUE
SELECT (g * 104729 % 400009) + 1,
       expiry - interval '90 days', expiry, expiry - interval '90 days',
       'cert-' || g || '.example', $2, $2,
       decode(lpad(to_hex(g), 64, '0'), 'hex'), false
FROM generate_series(1::bigint, 400000::bigint) AS g
CROSS JOIN LATERAL (
    SELECT CASE WHEN g % 5 = 0
                THEN $1::timestamp - interval '730 days' + g * interval '1 second'
                ELSE $1::timestamp + ((g * 104729 % 15552000) - 7776000) * interval '1 second'
           END AS expiry
) AS dates;`), cutoff, identID); err != nil {
		b.Fatalf("insert certificates: %v", err)
	}
	// Leave an old, deleted index prefix while retaining expired certificates
	// throughout the heap, including the first page window.
	if _, err := db.Exec(ctx, db.Pfx(`DELETE FROM CERTDB_cert WHERE notafter < $1;`), cutoff.AddDate(-1, 0, 0)); err != nil {
		b.Fatalf("leave dead index prefix: %v", err)
	}
	for _, query := range []string{
		`INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
SELECT id, false, 0, label || id, 'example'
FROM CERTDB_cert CROSS JOIN (VALUES ('one-'), ('two-')) AS names(label);`,
		`INSERT INTO CERTDB_ipaddress (cert, addr)
SELECT id, '192.0.2.1'::inet FROM CERTDB_cert;`,
		`INSERT INTO CERTDB_email (cert, email)
SELECT id, 'user-' || id || '@example.test' FROM CERTDB_cert;`,
		`INSERT INTO CERTDB_uri (cert, uri)
SELECT id, 'https://cert-' || id || '.example.test/' FROM CERTDB_cert;`,
		`ANALYZE CERTDB_cert; ANALYZE CERTDB_domain; ANALYZE CERTDB_ipaddress;
ANALYZE CERTDB_email; ANALYZE CERTDB_uri;`,
	} {
		if _, err := db.Exec(ctx, db.Pfx(query)); err != nil {
			b.Fatalf("prepare cleanup fixture: %v", err)
		}
	}

	if _, err := db.Exec(ctx, "CREATE EXTENSION pg_buffercache"); err != nil {
		b.Fatalf("enable local benchmark buffer eviction: %v", err)
	}

	const expiryQuery = `WITH CERTDB_clean_cert AS (
  SELECT ctid
  FROM CERTDB_cert
  WHERE notafter <= $1
  ORDER BY notafter ASC
  LIMIT $2
  FOR UPDATE SKIP LOCKED
), CERTDB_deleted_cert AS (
  DELETE FROM CERTDB_cert
  USING CERTDB_clean_cert
  WHERE CERTDB_cert.ctid = CERTDB_clean_cert.ctid
  RETURNING CERTDB_cert.notafter
)
SELECT count(*), max(notafter),
       pg_relation_size('CERTDB_cert') / current_setting('block_size')::bigint
FROM CERTDB_deleted_cert;`
	const certIDQuery = `WITH CERTDB_clean_cert AS MATERIALIZED (
  SELECT id, ctid
  FROM CERTDB_cert
  WHERE id > $3 AND id <= $4 AND notafter <= $1
  ORDER BY id
  LIMIT $2
  FOR UPDATE SKIP LOCKED
), CERTDB_deleted_cert AS (
  DELETE FROM CERTDB_cert
  WHERE ctid = ANY(ARRAY(SELECT ctid FROM CERTDB_clean_cert))
  RETURNING id
)
SELECT count(*), (SELECT max(id) FROM CERTDB_clean_cert),
       pg_relation_size('CERTDB_cert') / current_setting('block_size')::bigint
FROM CERTDB_deleted_cert;`
	for _, cache := range []string{"warm", "cold_shared_buffers"} {
		for _, tc := range []struct {
			name  string
			query string
			args  []any
		}{
			{name: "strategy=expiry_index", query: expiryQuery, args: []any{cutoff, batchSize}},
			{name: "strategy=cert_id", query: certIDQuery, args: []any{cutoff, batchSize, int64(0), int64(65536)}},
			{name: "strategy=storage_order", query: deleteCertificatesPageQuery, args: []any{cutoff, batchSize, pgtype.TID{Valid: true}, pgtype.TID{BlockNumber: cleanPagesPerBatch, Valid: true}}},
		} {
			b.Run("cache="+cache+"/"+tc.name, func(b *testing.B) {
				query := db.Pfx(tc.query)
				run := func(explain bool) (plan []byte) {
					tx, err := db.Begin(ctx)
					if err != nil {
						b.Fatalf("begin cleanup transaction: %v", err)
					}
					if explain {
						err = tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, tc.args...).Scan(&plan)
					} else {
						var deleted int64
						var blocks int64
						switch tc.name {
						case "strategy=expiry_index":
							var last sql.NullTime
							err = tx.QueryRow(ctx, query, tc.args...).Scan(&deleted, &last, &blocks)
						case "strategy=cert_id":
							var last sql.NullInt64
							err = tx.QueryRow(ctx, query, tc.args...).Scan(&deleted, &last, &blocks)
						default:
							var last pgtype.TID
							err = tx.QueryRow(ctx, query, tc.args...).Scan(&deleted, &last, &blocks)
						}
						if err == nil && deleted != batchSize {
							b.Errorf("deleted %d certificates, want %d", deleted, batchSize)
						}
					}
					if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
						b.Fatalf("roll back cleanup transaction: %v", rollbackErr)
					}
					if err != nil {
						b.Fatalf("delete cleanup batch: %v", err)
					}
					return
				}
				evict := func() {
					if _, err := db.Exec(ctx, "SELECT pg_buffercache_evict_all()"); err != nil {
						b.Fatalf("evict local benchmark buffers: %v", err)
					}
				}
				if cache == "cold_shared_buffers" {
					evict()
				}
				plan := run(true)
				var summary []struct {
					Plan struct {
						SharedHitBlocks  int64 `json:"Shared Hit Blocks"`
						SharedReadBlocks int64 `json:"Shared Read Blocks"`
					} `json:"Plan"`
					ExecutionTime float64 `json:"Execution Time"`
				}
				if err := json.Unmarshal(plan, &summary); err != nil || len(summary) != 1 {
					b.Fatalf("decode cleanup plan: %v (%d summaries)", err, len(summary))
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if cache == "cold_shared_buffers" {
						b.StopTimer()
						evict()
						b.StartTimer()
					}
					run(false)
				}
				b.StopTimer()
				b.ReportMetric(batchSize, "rows/op")
				b.ReportMetric(float64(batchSize)*float64(b.N)/b.Elapsed().Seconds(), "certs/s")
				b.ReportMetric(float64(summary[0].Plan.SharedHitBlocks+summary[0].Plan.SharedReadBlocks), "plan_buffers/op")
				b.ReportMetric(summary[0].ExecutionTime, "explain_ms/op")
				b.ReportMetric(float64(summary[0].Plan.SharedReadBlocks), "plan_reads/op")
			})
		}
	}
}
