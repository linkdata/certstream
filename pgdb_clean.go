package certstream

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// CleanBatchSize limits the certificates automatic cleanup deletes per statement.
var CleanBatchSize = 10000

// CleanResetInterval is the pause after a completed certificate cleanup sweep.
//
// Each sweep revisits skipped locks and certificates inserted behind its position.
var CleanResetInterval = time.Hour

const cleanPagesPerBatch = 256

const deleteCertificatesPageQuery = `WITH CERTDB_clean_cert AS MATERIALIZED (
  SELECT ctid
  FROM CERTDB_cert
  WHERE ctid > $3::tid AND ctid < $4::tid AND notafter <= $1
  ORDER BY ctid
  LIMIT $2
  FOR UPDATE SKIP LOCKED
), CERTDB_deleted_cert AS (
  DELETE FROM CERTDB_cert
  WHERE ctid = ANY(ARRAY(SELECT ctid FROM CERTDB_clean_cert))
  RETURNING CERTDB_cert.ctid
)
SELECT count(*),
       (SELECT ctid FROM CERTDB_clean_cert ORDER BY ctid DESC LIMIT 1),
       pg_relation_size('CERTDB_cert'::regclass) / current_setting('block_size')::bigint
FROM CERTDB_deleted_cert;`

// DeleteCertificates deletes up to batchSize expired certificates in storage order.
//
// Certificates expiring at or before cutoff are eligible. Deletion cascades to
// their domain, IP address, email and URI rows; CT log entries are left alone.
// Each statement selects from a bounded range of adjacent heap pages. Empty ranges
// are crossed in separate transactions until a deletion or the end of the sweep.
// A sweep examines the whole heap, so sparse cleanup can still take a long time.
//
// Calls on the same PgDB serialize and resume the current sweep. Progress is
// checkpointed after the first processed range, once per minute thereafter, and
// on sweep completion. A new PgDB resumes the checkpoint; uncheckpointed work
// can be repeated. A checkpoint from a different physical heap is discarded.
// Concurrent PgDBs may repeat work through their shared checkpoint.
//
// Each sweep covers the heap size at its start. Later sweeps revisit certificates
// that expire, are inserted or move behind the cursor, as well as skipped locks
// and table rewrites. After a sweep completes, calls return zero until
// [CleanResetInterval] has passed. If saving a checkpoint fails, rowsDeleted can
// be positive with a non-nil error because deletion has already committed.
// A nil PgDB or a batchSize below one deletes nothing.
func (cdb *PgDB) DeleteCertificates(ctx context.Context, cutoff time.Time, batchSize int) (rowsDeleted int64, err error) {
	if cdb != nil {
		cdb.beginCall()
		defer cdb.endCall()
		if batchSize > 0 {
			cdb.cleanMu.Lock()
			defer cdb.cleanMu.Unlock()
			if !cdb.cleanLoaded {
				if err = cdb.loadCleanState(ctx); err != nil {
					return
				}
			}
			if cdb.cleanEnd == 0 {
				if !cdb.cleanResetAt.IsZero() && time.Since(cdb.cleanResetAt) < CleanResetInterval {
					if cdb.cleanSavedAt.Before(cdb.cleanResetAt) {
						err = cdb.saveCleanState(ctx, true)
					}
					return
				}
				if err = cdb.QueryRow(ctx, cdb.Pfx(`SELECT pg_relation_filenode('CERTDB_cert'::regclass),
pg_relation_size('CERTDB_cert'::regclass) / current_setting('block_size')::bigint;`)).Scan(&cdb.cleanFile, &cdb.cleanEnd); err != nil {
					return
				}
				cdb.cleanFrom = pgtype.TID{Valid: true}
				cdb.cleanResetAt = time.Time{}
				cdb.cleanSavedAt = time.Time{}
			}
			for cdb.cleanEnd > 0 && ctx.Err() == nil {
				end := uint32(min(uint64(cdb.cleanEnd), uint64(cdb.cleanFrom.BlockNumber)+cleanPagesPerBatch))
				upper := pgtype.TID{BlockNumber: end, Valid: true}
				var last pgtype.TID
				var blocks uint32
				if err = cdb.QueryRow(ctx, cdb.Pfx(deleteCertificatesPageQuery), cutoff.UTC(), batchSize, cdb.cleanFrom, upper).Scan(&rowsDeleted, &last, &blocks); err != nil {
					return
				}
				// A full batch can stop within a page; keep its tuple offset.
				if rowsDeleted == int64(batchSize) && last.Valid {
					cdb.cleanFrom = last
				} else {
					cdb.cleanFrom = upper
				}
				cdb.cleanEnd = min(cdb.cleanEnd, blocks)
				if cdb.cleanFrom.BlockNumber >= cdb.cleanEnd {
					cdb.cleanEnd = 0
					cdb.cleanResetAt = time.Now()
				}
				if err = cdb.saveCleanState(ctx, cdb.cleanEnd == 0); err != nil {
					return
				}
				if rowsDeleted > 0 {
					return
				}
			}
			if err = ctx.Err(); err == nil && cdb.cleanEnd == 0 && cdb.cleanResetAt.IsZero() {
				cdb.cleanResetAt = time.Now()
				err = cdb.saveCleanState(ctx, true)
			}
		}
	}
	return
}

func (cdb *PgDB) loadCleanState(ctx context.Context) (err error) {
	var blocks, savedFile uint32
	var completed pgtype.Timestamptz
	if err = cdb.QueryRow(ctx, cdb.Pfx(`SELECT pg_relation_filenode('CERTDB_cert'::regclass),
       pg_relation_size('CERTDB_cert'::regclass) / current_setting('block_size')::bigint,
       COALESCE(s.relfilenode, 0), COALESCE(s.cursor_tid, '(0,0)'::tid),
       COALESCE(s.end_block, 0), s.completed_at
FROM (SELECT 1) AS singleton
LEFT JOIN CERTDB_cert_cleanup s ON s.id = 1;`)).Scan(&cdb.cleanFile, &blocks, &savedFile, &cdb.cleanFrom, &cdb.cleanEnd, &completed); err == nil {
		if savedFile == cdb.cleanFile {
			cdb.cleanEnd = min(cdb.cleanEnd, blocks)
			if completed.Valid {
				cdb.cleanResetAt = completed.Time
				cdb.cleanSavedAt = completed.Time
			}
		} else {
			cdb.cleanFrom = pgtype.TID{Valid: true}
			cdb.cleanEnd = blocks
		}
		cdb.cleanLoaded = true
	}
	return
}

func (cdb *PgDB) saveCleanState(ctx context.Context, force bool) (err error) {
	if force || cdb.cleanSavedAt.IsZero() || time.Since(cdb.cleanSavedAt) >= time.Minute {
		var completed *time.Time
		if !cdb.cleanResetAt.IsZero() {
			completed = &cdb.cleanResetAt
		}
		// Keep the generation captured with the sweep. A rewrite makes this
		// checkpoint stale, so reopening the database starts at the new heap.
		if _, err = cdb.Exec(ctx, cdb.Pfx(`INSERT INTO CERTDB_cert_cleanup
    (id, relfilenode, cursor_tid, end_block, completed_at)
VALUES (1, $1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET relfilenode = EXCLUDED.relfilenode,
    cursor_tid = EXCLUDED.cursor_tid, end_block = EXCLUDED.end_block,
    completed_at = EXCLUDED.completed_at;`), cdb.cleanFile, cdb.cleanFrom, cdb.cleanEnd, completed); err == nil {
			cdb.cleanSavedAt = time.Now()
		}
	}
	return
}

// CleanCertificates deletes expired certificates until ctx is done.
//
// Certificates become eligible once Config.PgCertMaxAge has passed since
// expiry. A PgCertMaxAge of zero or less returns immediately without
// deleting anything. [Start] runs this for the lifetime of the CertStream,
// so callers need it only when driving a [PgDB] themselves.
func (cdb *PgDB) CleanCertificates(ctx context.Context) {
	maxAge := cdb.PgCertMaxAge
	if maxAge <= 0 {
		return
	}
	for ctx.Err() == nil {
		rowsDeleted, err := cdb.DeleteCertificates(ctx, time.Now().UTC().Add(-maxAge), CleanBatchSize)
		if cdb.LogError(err, "CleanCertificates") != nil || rowsDeleted == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(time.Minute):
			}
		}
	}
}
