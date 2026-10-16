package certstream

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// BenchmarkPgDB_DeleteCertificatesPlanning measures planning a bounded heap
// window with live certificates and with a deleted expiry-index prefix.
//
// EXPLAIN does not execute the delete. Compare revisions with -benchtime=50x
// -count=6; the database metrics describe the final plan in each sample.
func BenchmarkPgDB_DeleteCertificatesPlanning(b *testing.B) {
	ctx, db, _, _, identID := cleanTestFixture(b)
	cutoff := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

	if _, err := db.Exec(ctx, db.Pfx(`ALTER TABLE CERTDB_cert SET (autovacuum_enabled = false)`)); err != nil {
		b.Fatalf("disable autovacuum: %v", err)
	}
	// Keep live expiry dates on both sides of cutoff after deleting the old
	// prefix, while its index entries remain until vacuum removes them.
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_cert
    (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
SELECT expiry - interval '1 day', expiry, expiry - interval '1 day',
       'cleanup-benchmark.example', $2, $2,
       decode(lpad(to_hex(g), 64, '0'), 'hex'), false
FROM generate_series(1, 120000) AS g
CROSS JOIN LATERAL (
    SELECT CASE WHEN g <= 100000
                THEN $1::timestamp - interval '30 days' + g * interval '1 second'
                ELSE $1::timestamp + (g - 110000) * interval '1 second'
           END AS expiry
) AS dates;`), cutoff, identID); err != nil {
		b.Fatalf("insert certificates: %v", err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`ANALYZE CERTDB_cert;`)); err != nil {
		b.Fatalf("analyze certificates: %v", err)
	}

	for _, tc := range []struct {
		name       string
		deadPrefix bool
	}{
		{name: "live_heap"},
		{name: "dead_prefix", deadPrefix: true},
	} {
		if tc.deadPrefix {
			if _, err := db.Exec(ctx, db.Pfx(`DELETE FROM CERTDB_cert WHERE notafter < $1;`), cutoff.Add(-24*time.Hour)); err != nil {
				b.Fatalf("leave dead index prefix: %v", err)
			}
			if _, err := db.Exec(ctx, db.Pfx(`ANALYZE CERTDB_cert;`)); err != nil {
				b.Fatalf("analyze deleted prefix: %v", err)
			}
		}
		b.Run(tc.name, func(b *testing.B) {
			explain := "EXPLAIN (BUFFERS, SUMMARY, FORMAT JSON) " + db.Pfx(deleteCertificatesPageQuery)
			args := []any{cutoff, 1000, pgtype.TID{Valid: true}, pgtype.TID{BlockNumber: cleanPagesPerBatch, Valid: true}}
			var plan []byte
			if err := db.QueryRow(ctx, explain, args...).Scan(&plan); err != nil {
				b.Fatalf("warm cleanup planner: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := db.QueryRow(ctx, explain, args...).Scan(&plan); err != nil {
					b.Fatalf("plan cleanup: %v", err)
				}
			}
			b.StopTimer()
			var summary []struct {
				PlanningTime float64 `json:"Planning Time"`
				Planning     struct {
					SharedHitBlocks  int64 `json:"Shared Hit Blocks"`
					SharedReadBlocks int64 `json:"Shared Read Blocks"`
				} `json:"Planning"`
			}
			if err := json.Unmarshal(plan, &summary); err != nil {
				b.Fatalf("decode cleanup plan: %v", err)
			}
			if len(summary) != 1 {
				b.Fatalf("cleanup plan has %d summaries, want 1", len(summary))
			}
			// The database metrics sample the final plan; ns/op includes every plan.
			b.ReportMetric(summary[0].PlanningTime, "last_db_plan_ms")
			b.ReportMetric(float64(summary[0].Planning.SharedHitBlocks+summary[0].Planning.SharedReadBlocks), "last_db_plan_buffers")
		})
	}
}
