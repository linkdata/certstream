package certstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestDeleteCertificatesPageQuery(t *testing.T) {
	t.Parallel()
	ctx, db, _, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	for i, expiry := range []time.Time{cutoff, cutoff, cutoff.Add(time.Second), cutoff} {
		if err := insertCleanTestCert(ctx, db, identID, expiry, i+1); err != nil {
			t.Fatalf("insert certificate: %v", err)
		}
	}
	var lower, upper, wantLast pgtype.TID
	for id, dest := range map[int]*pgtype.TID{1: &lower, 2: &wantLast, 4: &upper} {
		if err := db.QueryRow(ctx, db.Pfx(`SELECT ctid FROM CERTDB_cert WHERE id = $1`), id).Scan(dest); err != nil {
			t.Fatalf("read certificate position: %v", err)
		}
	}
	var deleted int64
	var last pgtype.TID
	var blocks uint32
	if err := db.QueryRow(ctx, db.Pfx(deleteCertificatesPageQuery), cutoff, 10, lower, upper).Scan(&deleted, &last, &blocks); err != nil {
		t.Fatalf("delete page range: %v", err)
	}
	if deleted != 1 || last != wantLast || blocks == 0 {
		t.Fatalf("delete page range = (%d, %v, %d blocks), want (1, %v, nonzero)", deleted, last, blocks, wantLast)
	}
	if count, err := countCerts(ctx, db); err != nil || count != 3 {
		t.Fatalf("certificates outside bounds or cutoff removed: count = %d, err = %v", count, err)
	}
}

// cleanTestFixture returns a database holding one operator, one stream and the
// default identity, ready for certificates to be inserted.
func cleanTestFixture(tb testing.TB) (ctx context.Context, db *PgDB, cs *CertStream, streamID int32, identID int32) {
	tb.Helper()
	ctx, db, cs = setupSelectGapsDB(tb)
	var operatorID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op','op@example.com') RETURNING id;`)).Scan(&operatorID); err != nil {
		tb.Fatalf("insert operator failed: %v", err)
	} else if err := insertStream(ctx, db, "https://example.com/log", operatorID, &streamID); err != nil {
		tb.Fatalf("insert stream failed: %v", err)
	} else if err := db.QueryRow(ctx, db.Pfx(`SELECT id FROM CERTDB_ident WHERE organization='' AND province='' AND country='';`)).Scan(&identID); err != nil {
		tb.Fatalf("default ident lookup failed: %v", err)
	}
	return
}

func insertCleanTestCert(ctx context.Context, db *PgDB, identID int32, notAfter time.Time, seed int) (err error) {
	_, err = db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
VALUES ($1, $2, $1, 'example.com', $3, $3, decode(lpad(to_hex($4::int), 64, '0'), 'hex'), false);`),
		notAfter.Add(-24*time.Hour), notAfter, identID, seed)
	return
}

func insertCleanTestEntry(ctx context.Context, db *PgDB, streamID int32, cert int32, logIndex int64, seen time.Time) (err error) {
	_, err = db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (seen, cert, logindex, stream) VALUES ($1, $2, $3, $4);`),
		seen, cert, logIndex, streamID)
	return
}

func countCerts(ctx context.Context, db *PgDB) (n int64, err error) {
	err = db.QueryRow(ctx, db.Pfx(`SELECT count(*) FROM CERTDB_cert;`)).Scan(&n)
	return
}

func TestPgDB_CleanCertificates_DisabledByDefault(t *testing.T) {
	t.Parallel()
	cdb := &PgDB{CertStream: &CertStream{}}
	cdb.CleanCertificates(t.Context()) // returns because PgCertMaxAge is zero
}

func TestPgDB_CleanCertificates_DeletesExpired(t *testing.T) {
	t.Parallel()
	ctx, db, cs, _, identID := cleanTestFixture(t)
	cs.PgCertMaxAge = time.Hour

	now := time.Now().UTC()
	if err := insertCleanTestCert(ctx, db, identID, now.Add(-48*time.Hour), 1); err != nil {
		t.Fatalf("insert expired cert failed: %v", err)
	}
	if err := insertCleanTestCert(ctx, db, identID, now.Add(48*time.Hour), 2); err != nil {
		t.Fatalf("insert live cert failed: %v", err)
	}

	// CleanCertificates blocks until ctx is done, so stop it once the expired
	// certificate is gone and the live one has been left alone.
	runCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		db.CleanCertificates(runCtx)
	}()

	deadline := time.Now().Add(30 * time.Second)
	for {
		if n, err := countCerts(ctx, db); err != nil {
			cancel()
			t.Fatalf("count certs failed: %v", err)
		} else if n == 1 {
			break
		} else if time.Now().After(deadline) {
			cancel()
			t.Fatalf("expired certificate still present, cert count = %d", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	// The live certificate must survive.
	if n, err := countCerts(ctx, db); err != nil {
		t.Fatalf("count certs failed: %v", err)
	} else if n != 1 {
		t.Fatalf("cert count after cleanup = %d, want 1", n)
	}
}

func TestPgDB_DeleteCertificates_DrainedCursor(t *testing.T) {
	t.Parallel()
	ctx, db, _, _, identID := cleanTestFixture(t)
	now := time.Now().UTC()
	cutoff := now.Add(-time.Hour)
	if err := insertCleanTestCert(ctx, db, identID, now.Add(-48*time.Hour), 1); err != nil {
		t.Fatalf("insert expired cert failed: %v", err)
	}
	if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil {
		t.Fatalf("DeleteCertificates failed: %v", err)
	} else if rowsDeleted != 1 {
		t.Fatalf("rows deleted = %d, want 1", rowsDeleted)
	}

	db.cleanMu.Lock()
	end, resetAt := db.cleanEnd, db.cleanResetAt
	db.cleanMu.Unlock()
	if end != 0 || resetAt.IsZero() {
		t.Fatalf("completed sweep state = (%d blocks, %v), want (0, completion time)", end, resetAt)
	}
	if err := insertCleanTestCert(ctx, db, identID, now.Add(-72*time.Hour), 2); err != nil {
		t.Fatalf("insert backfilled certificate: %v", err)
	}
	if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil {
		t.Fatalf("drained DeleteCertificates failed: %v", err)
	} else if rowsDeleted != 0 {
		t.Fatalf("rows deleted when drained = %d, want 0", rowsDeleted)
	}
	// The next sweep picks up certificates inserted behind its position.
	db.cleanMu.Lock()
	db.cleanResetAt = now.Add(-2 * CleanResetInterval)
	db.cleanMu.Unlock()
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil {
		t.Fatalf("sweeping DeleteCertificates failed: %v", err)
	} else if deleted != 1 {
		t.Fatalf("next sweep deleted %d certificates, want 1", deleted)
	}
}

func TestPgDB_DeleteCertificates_StartupAndResume(t *testing.T) {
	t.Parallel()
	ctx, db, _, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	old := cutoff.Add(-time.Hour)
	live := cutoff.Add(time.Second)
	for i, expiry := range []time.Time{old, cutoff, old.Add(-time.Hour), live} {
		if err := insertCleanTestCert(ctx, db, identID, expiry, i+1); err != nil {
			t.Fatalf("insert certificate %d failed: %v", i, err)
		}
	}

	var positions []pgtype.TID
	rows, err := db.Query(ctx, db.Pfx(`SELECT ctid FROM CERTDB_cert ORDER BY id`))
	if err != nil {
		t.Fatalf("read certificate positions: %v", err)
	}
	for rows.Next() {
		var position pgtype.TID
		if err := rows.Scan(&position); err != nil {
			rows.Close()
			t.Fatalf("read certificate position: %v", err)
		}
		positions = append(positions, position)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read certificate positions: %v", err)
	}
	rows.Close()
	if len(positions) != 4 || positions[0].BlockNumber != positions[2].BlockNumber {
		t.Fatalf("fixture must hold expired certificates on one page: %v", positions)
	}
	for call := 1; call <= 3; call++ {
		if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil {
			t.Fatalf("delete call %d failed: %v", call, err)
		} else if deleted != 1 {
			t.Fatalf("delete call %d removed %d certificates, want 1", call, deleted)
		}
		db.cleanMu.Lock()
		cursor := db.cleanFrom
		db.cleanMu.Unlock()
		if want := positions[call-1]; cursor != want {
			t.Fatalf("cursor after call %d = %v, want %v", call, cursor, want)
		}
	}

	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil {
		t.Fatalf("drained delete failed: %v", err)
	} else if deleted != 0 {
		t.Fatalf("drained delete removed %d certificates, want 0", deleted)
	}
	var remaining time.Time
	if err := db.QueryRow(ctx, db.Pfx(`SELECT notafter FROM CERTDB_cert;`)).Scan(&remaining); err != nil {
		t.Fatalf("read surviving certificate failed: %v", err)
	} else if !remaining.Equal(live) {
		t.Fatalf("surviving certificate expires at %v, want %v", remaining, live)
	}
}

func insertCleanTestPadding(t *testing.T, ctx context.Context, db *PgDB, identID int32, cutoff time.Time) {
	t.Helper()
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_cert
    (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
SELECT $1::timestamp, $1::timestamp + interval '1 day', $1::timestamp,
       repeat('x', 512), $2, $2, decode(lpad(to_hex(g), 64, '0'), 'hex'), false
FROM generate_series(1, 8000) AS g;`), cutoff, identID); err != nil {
		t.Fatalf("insert live page ranges: %v", err)
	}
}

func TestPgDB_DeleteCertificates_CrossesEmptyRanges(t *testing.T) {
	t.Parallel()
	ctx, db, _, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	insertCleanTestPadding(t, ctx, db, identID, cutoff)
	if err := insertCleanTestCert(ctx, db, identID, cutoff, 8001); err != nil {
		t.Fatalf("insert expired certificate: %v", err)
	}
	var position pgtype.TID
	if err := db.QueryRow(ctx, db.Pfx(`SELECT ctid FROM CERTDB_cert WHERE notafter <= $1`), cutoff).Scan(&position); err != nil {
		t.Fatalf("read expired certificate position: %v", err)
	}
	if position.BlockNumber < cleanPagesPerBatch {
		t.Fatalf("fixture has no empty page window before %v", position)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 1 {
		t.Fatalf("delete across empty ranges = (%d, %v), want (1, nil)", deleted, err)
	}
	if count, err := countCerts(ctx, db); err != nil || count != 8000 {
		t.Fatalf("surviving live certificates = (%d, %v), want (8000, nil)", count, err)
	}
}

func TestPgDB_DeleteCertificates_SkippedLocks(t *testing.T) {
	t.Parallel()
	ctx, db, _, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC()
	for seed := 1; seed <= 3; seed++ {
		if err := insertCleanTestCert(ctx, db, identID, cutoff.Add(-time.Hour), seed); err != nil {
			t.Fatalf("insert expired certificate: %v", err)
		}
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin row-lock transaction: %v", err)
	}
	t.Cleanup(func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("roll back row-lock transaction: %v", err)
		}
	})
	if _, err := tx.Exec(ctx, db.Pfx(`SELECT id FROM CERTDB_cert WHERE id = 1 FOR UPDATE`)); err != nil {
		t.Fatalf("lock expired certificate: %v", err)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 2 {
		t.Fatalf("delete with skipped lock = (%d, %v), want (2, nil)", deleted, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("release row lock: %v", err)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 0 {
		t.Fatalf("delete during sweep pause = (%d, %v), want (0, nil)", deleted, err)
	}
	db.cleanMu.Lock()
	db.cleanResetAt = time.Now().Add(-2 * CleanResetInterval)
	db.cleanMu.Unlock()
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 1 {
		t.Fatalf("next sweep after skipped lock = (%d, %v), want (1, nil)", deleted, err)
	}
}

func TestPgDB_DeleteCertificates_CanceledStatementKeepsCursor(t *testing.T) {
	t.Parallel()
	ctx, db, _, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC()
	for seed := 1; seed <= 3; seed++ {
		if err := insertCleanTestCert(ctx, db, identID, cutoff.Add(-time.Hour), seed); err != nil {
			t.Fatalf("insert expired certificate: %v", err)
		}
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("initial deletion = (%d, %v), want (1, nil)", deleted, err)
	}
	db.cleanMu.Lock()
	from, end := db.cleanFrom, db.cleanEnd
	db.cleanMu.Unlock()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin table-lock transaction: %v", err)
	}
	t.Cleanup(func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("roll back table-lock transaction: %v", err)
		}
	})
	if _, err := tx.Exec(ctx, db.Pfx(`LOCK TABLE CERTDB_cert IN ACCESS EXCLUSIVE MODE`)); err != nil {
		t.Fatalf("block cleanup statement: %v", err)
	}
	deleteCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := db.DeleteCertificates(deleteCtx, cutoff, 1)
		done <- err
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var blocked bool
		if err := db.QueryRow(ctx, db.Pfx(`SELECT EXISTS (
SELECT 1 FROM pg_locks WHERE relation = 'CERTDB_cert'::regclass AND NOT granted)`)).Scan(&blocked); err != nil {
			t.Fatalf("inspect blocked cleanup: %v", err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cleanup statement did not wait on the table lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cleanup error = %v, want context.Canceled", err)
	}
	db.cleanMu.Lock()
	gotFrom, gotEnd := db.cleanFrom, db.cleanEnd
	db.cleanMu.Unlock()
	if gotFrom != from || gotEnd != end {
		t.Fatalf("canceled statement advanced cursor from (%v, %d) to (%v, %d)", from, end, gotFrom, gotEnd)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("release table lock: %v", err)
	}
}

func TestPgDB_DeleteCertificates_TruncatedHeap(t *testing.T) {
	t.Parallel()
	ctx, db, _, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	insertCleanTestPadding(t, ctx, db, identID, cutoff)
	for seed := 8001; seed <= 8002; seed++ {
		if err := insertCleanTestCert(ctx, db, identID, cutoff, seed); err != nil {
			t.Fatalf("insert expired certificate: %v", err)
		}
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("initial deletion = (%d, %v), want (1, nil)", deleted, err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`TRUNCATE CERTDB_cert CASCADE`)); err != nil {
		t.Fatalf("truncate heap: %v", err)
	}
	if err := insertCleanTestCert(ctx, db, identID, cutoff, 9000); err != nil {
		t.Fatalf("insert certificate into truncated heap: %v", err)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 0 {
		t.Fatalf("finish truncated sweep = (%d, %v), want (0, nil)", deleted, err)
	}
	db.cleanMu.Lock()
	end := db.cleanEnd
	db.cleanResetAt = time.Now().Add(-2 * CleanResetInterval)
	db.cleanMu.Unlock()
	if end != 0 {
		t.Fatalf("truncated sweep still has %d blocks to inspect", end)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 1 {
		t.Fatalf("sweep reused heap pages = (%d, %v), want (1, nil)", deleted, err)
	}
}

// BenchmarkPgDB_DeleteCertificates measures polling during the pause after a
// completed sweep, when no further heap scan is needed.
func BenchmarkPgDB_DeleteCertificates(b *testing.B) {
	ctx, db, _, _, identID := cleanTestFixture(b)
	const gap = 20000
	base := time.Now().UTC().Add(-720 * time.Hour)
	for i := 0; i < gap; i++ {
		if err := insertCleanTestCert(ctx, db, identID, base.Add(time.Duration(i)*time.Second), i); err != nil {
			b.Fatalf("insert cert %d failed: %v", i, err)
		}
	}
	cutoff := time.Now().UTC()
	for {
		if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 5000); err != nil {
			b.Fatalf("drain failed: %v", err)
		} else if rowsDeleted == 0 {
			break
		}
	}
	// Confirm that polling the completed sweep succeeds before measuring.
	if _, err := db.DeleteCertificates(ctx, cutoff, CleanBatchSize); err != nil {
		b.Fatalf("settle failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := db.DeleteCertificates(ctx, cutoff, CleanBatchSize); err != nil {
			b.Fatalf("DeleteCertificates failed: %v", err)
		}
	}
}

func TestPgDB_DeleteStream_PersistsCursor(t *testing.T) {
	t.Parallel()
	ctx, db, _, streamID, identID := cleanTestFixture(t)

	cursor := func() (v int64) {
		if err := db.QueryRow(ctx, db.Pfx(`SELECT clean_logindex FROM CERTDB_stream WHERE id = $1;`), streamID).Scan(&v); err != nil {
			t.Fatalf("reading clean_logindex failed: %v", err)
		}
		return
	}

	// Stream ids that do not exist are not an error and leave no trace.
	for id := int32(10000); id < 10010; id++ {
		if rowsDeleted, err := db.DeleteStream(ctx, id, 10); err != nil {
			t.Fatalf("DeleteStream(%d) failed: %v", id, err)
		} else if rowsDeleted != 0 {
			t.Fatalf("rows deleted for missing stream %d = %d, want 0", id, rowsDeleted)
		}
	}

	now := time.Now().UTC()
	for i := range 6 {
		if err := insertCleanTestEntry(ctx, db, streamID, identID, int64(i+1), now); err != nil {
			t.Fatalf("insert entry failed: %v", err)
		}
	}
	if v := cursor(); v != 0 {
		t.Fatalf("cursor before any deletion = %d, want 0", v)
	}

	// Draining part of the stream records where to resume, so that a later
	// process does not start over at the first entry.
	if rowsDeleted, err := db.DeleteStream(ctx, streamID, 2); err != nil {
		t.Fatalf("DeleteStream failed: %v", err)
	} else if rowsDeleted != 2 {
		t.Fatalf("rows deleted = %d, want 2", rowsDeleted)
	}
	if v := cursor(); v != 3 {
		t.Fatalf("cursor after deleting logindex 1 and 2 = %d, want 3", v)
	}

	// A fresh PgDB, standing in for a restarted process, resumes from it.
	if other, err := NewPgDB(ctx, db.CertStream); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		defer other.Close()
		if rowsDeleted, err := other.DeleteStream(ctx, streamID, 2); err != nil {
			t.Fatalf("DeleteStream on a second handle failed: %v", err)
		} else if rowsDeleted != 2 {
			t.Fatalf("rows deleted by the second handle = %d, want 2", rowsDeleted)
		}
		if v := cursor(); v != 5 {
			t.Fatalf("cursor after the second handle = %d, want 5", v)
		}
	}

	// Draining the rest removes the stream, taking its cursor with it.
	for range 5 {
		if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
			t.Fatalf("DeleteStream failed: %v", err)
		} else if rowsDeleted == 0 {
			break
		}
	}
	var streamCount int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT count(*) FROM CERTDB_stream WHERE id = $1;`), streamID).Scan(&streamCount); err != nil {
		t.Fatalf("count failed: %v", err)
	} else if streamCount != 0 {
		t.Fatalf("stream count = %d, want 0", streamCount)
	}
}

// Not parallel: it writes CleanEmptyCheckTimeout, which the other DeleteStream
// tests read.
func TestPgDB_DeleteStream_EmptyCheckTimeoutKeepsStream(t *testing.T) {
	ctx, db, _, streamID, identID := cleanTestFixture(t)

	// Drain the stream so the cursor sits past the end, which is what makes the
	// next call restart the scan at the first entry.
	now := time.Now().UTC()
	for i := range 3 {
		if err := insertCleanTestEntry(ctx, db, streamID, identID, int64(i+1), now); err != nil {
			t.Fatalf("insert entry failed: %v", err)
		}
	}
	if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
		t.Fatalf("draining DeleteStream failed: %v", err)
	} else if rowsDeleted != 3 {
		t.Fatalf("rows deleted = %d, want 3", rowsDeleted)
	}

	// An unreachable budget stands in for a drained stream whose index entries
	// autovacuum has not removed yet, where both the restart scan and proving
	// emptiness take minutes.
	saved := CleanEmptyCheckTimeout
	CleanEmptyCheckTimeout = time.Nanosecond
	t.Cleanup(func() { CleanEmptyCheckTimeout = saved })

	cursor := func() (v int64) {
		if err := db.QueryRow(ctx, db.Pfx(`SELECT clean_logindex FROM CERTDB_stream WHERE id = $1;`), streamID).Scan(&v); err != nil {
			t.Fatalf("reading clean_logindex failed: %v", err)
		}
		return
	}
	drained := cursor()
	if drained == 0 {
		t.Fatal("cursor should sit past the drained entries")
	}

	if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
		t.Fatalf("DeleteStream failed: %v", err)
	} else if rowsDeleted != 0 {
		t.Fatalf("rows deleted = %d, want 0", rowsDeleted)
	}

	// The restart scan gave up, so the cursor must be left where it was. An
	// unbounded restart would have run to the end and reset it to 0, which is
	// how this distinguishes the two without depending on how slow the scan is.
	if v := cursor(); v != drained {
		t.Fatalf("cursor = %d, want %d unchanged: the restart scan was not bounded", v, drained)
	}

	var streamCount int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT count(*) FROM CERTDB_stream WHERE id = $1;`), streamID).Scan(&streamCount); err != nil {
		t.Fatalf("count failed: %v", err)
	} else if streamCount != 1 {
		t.Fatalf("stream count = %d, want 1: it must not be deleted without proof", streamCount)
	}

	// With a workable budget the same call removes it.
	CleanEmptyCheckTimeout = saved
	if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
		t.Fatalf("DeleteStream failed: %v", err)
	} else if rowsDeleted != 1 {
		t.Fatalf("rows deleted = %d, want 1", rowsDeleted)
	}
}

// BenchmarkPgDB_DeleteStream measures deleting one batch of log entries from a
// stream that already has a large emptied prefix, which is the walk the cursor
// exists to skip. Compare revisions with benchstat.
func BenchmarkPgDB_DeleteStream(b *testing.B) {
	ctx, db, _, streamID, _ := cleanTestFixture(b)
	const (
		total = 600000
		gap   = 200000
		batch = 100
	)
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (seen, cert, logindex, stream)
SELECT now(), g, g, $1 FROM generate_series(0, $2) g;`), streamID, total-1); err != nil {
		b.Fatalf("insert entries failed: %v", err)
	}
	for drained := int64(0); drained < gap; {
		rowsDeleted, err := db.DeleteStream(ctx, streamID, 10000)
		if err != nil {
			b.Fatalf("building the emptied prefix failed: %v", err)
		}
		if rowsDeleted == 0 {
			b.Fatal("stream drained while building the prefix")
		}
		drained += rowsDeleted
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rowsDeleted, err := db.DeleteStream(ctx, streamID, batch)
		if err != nil {
			b.Fatalf("DeleteStream failed: %v", err)
		}
		if rowsDeleted == 0 {
			b.Fatal("stream exhausted; raise total or lower -benchtime")
		}
	}
}

// BenchmarkPgDB_DeleteStreamAfterRestart measures the first batch a new process
// deletes from a stream that is already partly drained. That batch is the one
// the persisted cursor exists for: without it the scan starts at the first
// entry and walks everything already deleted. Compare revisions with benchstat.
func BenchmarkPgDB_DeleteStreamAfterRestart(b *testing.B) {
	ctx, db, cs, streamID, _ := cleanTestFixture(b)
	const (
		total = 400000
		gap   = 300000
		batch = 100
	)
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (seen, cert, logindex, stream)
SELECT now(), g, g, $1 FROM generate_series(0, $2) g;`), streamID, total-1); err != nil {
		b.Fatalf("insert entries failed: %v", err)
	}
	for drained := int64(0); drained < gap; {
		rowsDeleted, err := db.DeleteStream(ctx, streamID, 10000)
		if err != nil {
			b.Fatalf("building the emptied prefix failed: %v", err)
		}
		if rowsDeleted == 0 {
			b.Fatal("stream drained while building the prefix")
		}
		drained += rowsDeleted
	}

	b.ReportAllocs()
	for b.Loop() {
		// A fresh handle stands in for a restarted process: it has no cursor of
		// its own and must find where to resume.
		b.StopTimer()
		restarted, err := NewPgDB(ctx, cs)
		if err != nil {
			b.Fatalf("NewPgDB failed: %v", err)
		}
		b.StartTimer()

		rowsDeleted, err := restarted.DeleteStream(ctx, streamID, batch)

		b.StopTimer()
		restarted.Close()
		if err != nil {
			b.Fatalf("DeleteStream failed: %v", err)
		}
		if rowsDeleted == 0 {
			b.Fatal("stream exhausted; raise total or lower -benchtime")
		}
		b.StartTimer()
	}
}
