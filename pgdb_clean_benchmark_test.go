package certstream

import (
	"encoding/json"
	"testing"
	"time"
)

// BenchmarkPgDB_DeleteCertificatesPlanning measures planning a cleanup statement
// when deleted certificates still occupy the start of the expiry index.
//
// EXPLAIN does not execute the delete. Compare revisions with -benchtime=50x
// -count=6; the database metrics describe the final plan in each sample.
func BenchmarkPgDB_DeleteCertificatesPlanning(b *testing.B) {
	ctx, db, _, _, identID := cleanTestFixture(b)
	cutoff := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

	if _, err := db.Exec(ctx, db.Pfx(`ALTER TABLE CERTDB_cert SET (autovacuum_enabled = false)`)); err != nil {
		b.Fatalf("disable autovacuum: %v", err)
	}
	// Keep live expiry dates on both sides of cutoff so only the year-one
	// lower bound, when present, reaches the histogram's oldest endpoint.
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
	if _, err := db.Exec(ctx, db.Pfx(`DELETE FROM CERTDB_cert WHERE notafter < $1;`), cutoff.Add(-24*time.Hour)); err != nil {
		b.Fatalf("leave dead index prefix: %v", err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`ANALYZE CERTDB_cert;`)); err != nil {
		b.Fatalf("analyze certificates: %v", err)
	}
	// An ordered scan marks the deleted prefix dead in the index while leaving
	// its pages in place for the planner's endpoint probe.
	var firstLiveCTID string
	if err := db.QueryRow(ctx, db.Pfx(`SELECT ctid::text FROM CERTDB_cert WHERE notafter <= $1 ORDER BY notafter LIMIT 1`), cutoff).Scan(&firstLiveCTID); err != nil {
		b.Fatalf("scan dead index prefix: %v", err)
	}
	// Load planner metadata without touching the dead low end of the index.
	warmQuery, warmArgs := deleteCertificatesQuery(cutoff.Add(-time.Hour), cutoff, 1000)
	var warmPlan []byte
	if err := db.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+db.Pfx(warmQuery), warmArgs...).Scan(&warmPlan); err != nil {
		b.Fatalf("warm planner metadata: %v", err)
	}

	for _, tc := range []struct {
		name string
		from time.Time
	}{
		{name: "reset_cursor"},
		{name: "resumed_cursor", from: cutoff.Add(-time.Hour)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			query, args := deleteCertificatesQuery(tc.from, cutoff, 1000)
			explain := "EXPLAIN (BUFFERS, SUMMARY, FORMAT JSON) " + db.Pfx(query)
			var plan []byte
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
