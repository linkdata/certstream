package certstream

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// BenchmarkPgDB_DeleteCertificatesAfterRestart measures cleanup after restarting.
//
// An expired marker and target follow a live heap prefix. The fixture seeds a
// durable checkpoint after the marker. Each iteration opens a fresh handle and
// deletes the target. Opening the handle and restoring the target are untimed.
// Autovacuum is disabled to keep the physical fixture stable.
// Compare revisions with -benchtime=20x -count=6; shared and OS caches remain warm.
func BenchmarkPgDB_DeleteCertificatesAfterRestart(b *testing.B) {
	ctx, db, cs, _, identID := cleanTestFixture(b)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	const prefix = 40000
	if _, err := db.Exec(ctx, db.Pfx(`
ALTER TABLE CERTDB_cert SET (autovacuum_enabled = false);
INSERT INTO CERTDB_cert
    (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
SELECT $1::timestamp, $1::timestamp + interval '1 day', $1::timestamp,
       repeat('x', 512), $2, $2, decode(lpad(to_hex(g), 64, '0'), 'hex'), false
FROM generate_series(1, $3::int) AS g;`), cutoff, identID, prefix); err != nil {
		b.Fatalf("insert live heap prefix: %v", err)
	}
	for _, seed := range []int{prefix + 1, prefix + 2} {
		if err := insertCleanTestCert(ctx, db, identID, cutoff, seed); err != nil {
			b.Fatalf("insert expired tail certificate: %v", err)
		}
	}
	var marker pgtype.TID
	if err := db.QueryRow(ctx, db.Pfx(`SELECT ctid FROM CERTDB_cert
WHERE sha256 = decode(lpad(to_hex($1::int), 64, '0'), 'hex');`), prefix+1).Scan(&marker); err != nil {
		b.Fatalf("read marker position: %v", err)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		b.Fatalf("establish cleanup position: deleted=%d, want 1: %v", deleted, err)
	}
	// Prepare the same checkpoint when comparing revisions.
	if _, err := db.Exec(ctx, db.Pfx(`
CREATE TABLE IF NOT EXISTS CERTDB_cert_cleanup (
    id INTEGER PRIMARY KEY CHECK (id = 1), relfilenode OID NOT NULL,
    cursor_tid TID NOT NULL, end_block BIGINT NOT NULL, completed_at TIMESTAMPTZ
);
INSERT INTO CERTDB_cert_cleanup (id, relfilenode, cursor_tid, end_block, completed_at)
SELECT 1, pg_relation_filenode('CERTDB_cert'::regclass), $1,
       pg_relation_size('CERTDB_cert'::regclass) / current_setting('block_size')::bigint, NULL
ON CONFLICT (id) DO UPDATE SET relfilenode = EXCLUDED.relfilenode,
    cursor_tid = EXCLUDED.cursor_tid, end_block = EXCLUDED.end_block,
    completed_at = EXCLUDED.completed_at;`), marker); err != nil {
		b.Fatalf("seed durable cleanup position: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		restarted, err := NewPgDB(ctx, cs)
		if err != nil {
			b.Fatalf("open restarted database handle: %v", err)
		}
		b.StartTimer()
		deleted, err := restarted.DeleteCertificates(ctx, cutoff, 1)
		b.StopTimer()
		restarted.Close()
		if err != nil || deleted != 1 {
			b.Fatalf("cleanup after restart: deleted=%d, want 1: %v", deleted, err)
		}
		if err := insertCleanTestCert(ctx, db, identID, cutoff, prefix+2); err != nil {
			b.Fatalf("restore expired target: %v", err)
		}
		b.StartTimer()
	}
}
