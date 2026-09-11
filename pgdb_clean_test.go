package certstream

import (
	"context"
	"testing"
	"time"
)

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
	cs.Config.PgCertMaxAge = time.Hour

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

	// Skip the sweep the zero cleanResetAt would otherwise allow, so this
	// exercises the drained branch.
	db.mu.Lock()
	db.cleanResetAt = now
	db.mu.Unlock()
	if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil {
		t.Fatalf("drained DeleteCertificates failed: %v", err)
	} else if rowsDeleted != 0 {
		t.Fatalf("rows deleted when drained = %d, want 0", rowsDeleted)
	}
	db.mu.Lock()
	cleanFrom := db.cleanFrom
	db.mu.Unlock()
	if !cleanFrom.Equal(cutoff) {
		t.Fatalf("cleanFrom after drained call = %v, want cutoff %v", cleanFrom, cutoff)
	}

	// Once CleanResetInterval has passed the cursor sweeps back.
	db.mu.Lock()
	db.cleanResetAt = now.Add(-2 * CleanResetInterval)
	db.mu.Unlock()
	if _, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil {
		t.Fatalf("sweeping DeleteCertificates failed: %v", err)
	}
	db.mu.Lock()
	cleanFrom = db.cleanFrom
	db.mu.Unlock()
	if !cleanFrom.IsZero() {
		t.Fatalf("cleanFrom after sweep = %v, want zero", cleanFrom)
	}
}

// BenchmarkPgDB_DeleteCertificates measures a drained cleanup cycle over a
// range whose certificates have already been deleted, which is what the
// cursor exists to skip. Compare revisions with benchstat.
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
	// Settle the cursor past the emptied range before measuring.
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

func TestPgDB_DeleteStream_KeepsNoCursorForEmptyOrMissing(t *testing.T) {
	t.Parallel()
	ctx, db, _, streamID, identID := cleanTestFixture(t)

	cursorCount := func() (n int) {
		db.mu.Lock()
		n = len(db.cleanStream)
		db.mu.Unlock()
		return
	}

	// Stream ids that were never created must not accumulate cursors.
	for id := int32(10000); id < 10100; id++ {
		if rowsDeleted, err := db.DeleteStream(ctx, id, 10); err != nil {
			t.Fatalf("DeleteStream(%d) failed: %v", id, err)
		} else if rowsDeleted != 0 {
			t.Fatalf("rows deleted for missing stream %d = %d, want 0", id, rowsDeleted)
		}
	}
	if n := cursorCount(); n != 0 {
		t.Fatalf("cursors retained for missing streams = %d, want 0", n)
	}

	// A partly drained stream keeps its cursor, otherwise the next call starts
	// over from the beginning.
	now := time.Now().UTC()
	for i := range 4 {
		if err := insertCleanTestEntry(ctx, db, streamID, identID, int64(i+1), now); err != nil {
			t.Fatalf("insert entry failed: %v", err)
		}
	}
	if rowsDeleted, err := db.DeleteStream(ctx, streamID, 2); err != nil {
		t.Fatalf("DeleteStream failed: %v", err)
	} else if rowsDeleted != 2 {
		t.Fatalf("rows deleted = %d, want 2", rowsDeleted)
	}
	if n := cursorCount(); n != 1 {
		t.Fatalf("cursors after a partial drain = %d, want 1", n)
	}

	// Draining it fully and removing the stream leaves nothing behind.
	for range 5 {
		if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
			t.Fatalf("DeleteStream failed: %v", err)
		} else if rowsDeleted == 0 {
			break
		}
	}
	if n := cursorCount(); n != 0 {
		t.Fatalf("cursors after the stream was removed = %d, want 0", n)
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
