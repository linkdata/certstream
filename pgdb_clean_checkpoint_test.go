package certstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type cleanCheckpoint struct {
	file      uint32
	from      pgtype.TID
	end       uint32
	completed pgtype.Timestamptz
}

func readCleanCheckpoint(t *testing.T, ctx context.Context, db *PgDB) (state cleanCheckpoint) {
	t.Helper()
	if err := db.QueryRow(ctx, db.Pfx(`SELECT relfilenode, cursor_tid, end_block, completed_at
FROM CERTDB_cert_cleanup WHERE id = 1`)).Scan(&state.file, &state.from, &state.end, &state.completed); err != nil {
		t.Fatalf("read cleanup checkpoint: %v", err)
	}
	return
}

func reopenCleanCheckpointDB(t *testing.T, ctx context.Context, cs *CertStream) (db *PgDB) {
	t.Helper()
	var err error
	if db, err = NewPgDB(ctx, cs); err != nil {
		t.Fatalf("reopen cleanup database: %v", err)
	}
	t.Cleanup(db.Close)
	return
}

func TestPgDB_DeleteCertificates_CheckpointResume(t *testing.T) {
	t.Parallel()
	ctx, db, cs, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	positions := make([]pgtype.TID, 4)
	for i := range positions {
		if err := insertCleanTestCert(ctx, db, identID, cutoff, i+1); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, db.Pfx(`SELECT ctid FROM CERTDB_cert WHERE id = $1`), i+1).Scan(&positions[i]); err != nil {
			t.Fatal(err)
		}
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("first deletion=(%d, %v), want (1, nil)", deleted, err)
	}
	first := readCleanCheckpoint(t, ctx, db)
	if first.from != positions[0] || first.end == 0 || first.completed.Valid {
		t.Fatalf("first checkpoint=%+v, want active cursor %v", first, positions[0])
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if deleted, err := db.DeleteCertificates(canceled, cutoff, 1); !errors.Is(err, context.Canceled) || deleted != 0 {
		t.Fatalf("canceled deletion=(%d, %v), want (0, context.Canceled)", deleted, err)
	}
	if got := readCleanCheckpoint(t, ctx, db); got != first {
		t.Fatalf("canceled deletion changed checkpoint: %+v, want %+v", got, first)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("uncheckpointed deletion=(%d, %v), want (1, nil)", deleted, err)
	}
	if got := readCleanCheckpoint(t, ctx, db); got != first {
		t.Fatalf("checkpoint changed before its interval: %+v, want %+v", got, first)
	}
	db.cleanMu.Lock()
	db.cleanSavedAt = time.Now().Add(-2 * time.Minute)
	db.cleanMu.Unlock()
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("periodic deletion=(%d, %v), want (1, nil)", deleted, err)
	}
	saved := readCleanCheckpoint(t, ctx, db)
	if saved.from != positions[2] || saved.end != first.end || saved.file != first.file {
		t.Fatalf("periodic checkpoint=%+v, want cursor %v", saved, positions[2])
	}
	restarted := reopenCleanCheckpointDB(t, ctx, cs)
	if err := restarted.loadCleanState(ctx); err != nil {
		t.Fatal(err)
	}
	if restarted.cleanFrom != saved.from || restarted.cleanEnd != saved.end || restarted.cleanFile != saved.file {
		t.Fatalf("restart state=(%v, %d, %d), want %+v", restarted.cleanFrom, restarted.cleanEnd, restarted.cleanFile, saved)
	}
	if deleted, err := restarted.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("resumed deletion=(%d, %v), want (1, nil)", deleted, err)
	}
	if got := readCleanCheckpoint(t, ctx, restarted); got.from != positions[3] {
		t.Fatalf("resumed checkpoint=%+v, want cursor %v", got, positions[3])
	}
}

func TestPgDB_DeleteCertificates_CheckpointResumeDefersEarlierExpiry(t *testing.T) {
	t.Parallel()
	ctx, db, cs, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	for i, expiry := range []time.Time{cutoff.Add(time.Hour), cutoff, cutoff} {
		if err := insertCleanTestCert(ctx, db, identID, expiry, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("establish checkpoint=(%d, %v), want (1, nil)", deleted, err)
	}
	// Advancing the cutoff makes the earlier row eligible behind the checkpoint.
	later := cutoff.Add(2 * time.Hour)
	restarted := reopenCleanCheckpointDB(t, ctx, cs)
	if deleted, err := restarted.DeleteCertificates(ctx, later, 1); err != nil || deleted != 1 {
		t.Fatalf("resume through public API=(%d, %v), want (1, nil)", deleted, err)
	}
	var early, tail int
	if err := db.QueryRow(ctx, db.Pfx(`SELECT
    count(*) FILTER (WHERE id=1), count(*) FILTER (WHERE id=3)
FROM CERTDB_cert`)).Scan(&early, &tail); err != nil {
		t.Fatal(err)
	}
	if early != 1 || tail != 0 {
		t.Fatalf("after resume: early=%d, tail=%d, want (1, 0)", early, tail)
	}
	if deleted, err := restarted.DeleteCertificates(ctx, later, 10); err != nil || deleted != 0 {
		t.Fatalf("finish resumed sweep=(%d, %v), want (0, nil)", deleted, err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`UPDATE CERTDB_cert_cleanup SET completed_at=$1 WHERE id=1`), time.Now().Add(-2*CleanResetInterval)); err != nil {
		t.Fatal(err)
	}
	next := reopenCleanCheckpointDB(t, ctx, cs)
	if deleted, err := next.DeleteCertificates(ctx, later, 10); err != nil || deleted != 1 {
		t.Fatalf("rewound sweep=(%d, %v), want earlier certificate removed", deleted, err)
	}
}

func TestPgDB_DeleteCertificates_CheckpointsEmptyRanges(t *testing.T) {
	t.Parallel()
	ctx, db, cs, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	insertCleanTestPadding(t, ctx, db, identID, cutoff)
	if err := insertCleanTestCert(ctx, db, identID, cutoff, 8001); err != nil {
		t.Fatal(err)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("deletion after live prefix=(%d, %v), want (1, nil)", deleted, err)
	}
	saved := readCleanCheckpoint(t, ctx, db)
	want := pgtype.TID{BlockNumber: cleanPagesPerBatch, Valid: true}
	if saved.from != want || saved.end <= cleanPagesPerBatch || saved.completed.Valid {
		t.Fatalf("empty-range checkpoint=%+v, want active cursor %v", saved, want)
	}
	restarted := reopenCleanCheckpointDB(t, ctx, cs)
	if err := restarted.loadCleanState(ctx); err != nil {
		t.Fatal(err)
	}
	if restarted.cleanFrom != saved.from || restarted.cleanEnd != saved.end {
		t.Fatalf("resumed empty-range state=(%v, %d), want %+v", restarted.cleanFrom, restarted.cleanEnd, saved)
	}
}

func TestPgDB_DeleteCertificates_CheckpointHeapChanged(t *testing.T) {
	for _, operation := range []string{"TRUNCATE CERTDB_cert CASCADE", "VACUUM FULL CERTDB_cert"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			ctx, db, cs, _, identID := cleanTestFixture(t)
			cutoff := time.Now().UTC().Truncate(time.Microsecond)
			for seed := 1; seed <= 2; seed++ {
				if err := insertCleanTestCert(ctx, db, identID, cutoff, seed); err != nil {
					t.Fatal(err)
				}
			}
			if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
				t.Fatalf("first deletion=(%d, %v), want (1, nil)", deleted, err)
			}
			before := readCleanCheckpoint(t, ctx, db)
			if _, err := db.Exec(ctx, db.Pfx(operation)); err != nil {
				t.Fatal(err)
			}
			if operation == "TRUNCATE CERTDB_cert CASCADE" {
				if err := insertCleanTestCert(ctx, db, identID, cutoff, 3); err != nil {
					t.Fatal(err)
				}
			}
			restarted := reopenCleanCheckpointDB(t, ctx, cs)
			if deleted, err := restarted.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 1 {
				t.Fatalf("deletion after heap change=(%d, %v), want (1, nil)", deleted, err)
			}
			if got := readCleanCheckpoint(t, ctx, restarted); got.file == before.file {
				t.Fatalf("checkpoint still refers to replaced heap %d", before.file)
			}
		})
	}
}

func TestPgDB_DeleteCertificates_CheckpointCompletionRetry(t *testing.T) {
	t.Parallel()
	ctx, db, cs, _, identID := cleanTestFixture(t)
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	for i, expiry := range []time.Time{cutoff, cutoff, cutoff.Add(time.Hour)} {
		if err := insertCleanTestCert(ctx, db, identID, expiry, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("first deletion=(%d, %v), want (1, nil)", deleted, err)
	}
	before := readCleanCheckpoint(t, ctx, db)
	if _, err := db.Exec(ctx, db.Pfx(`ALTER TABLE CERTDB_cert_cleanup
ADD CONSTRAINT reject_checkpoint CHECK (false) NOT VALID`)); err != nil {
		t.Fatal(err)
	}
	deleted, err := db.DeleteCertificates(ctx, cutoff, 10)
	var pgerr *pgconn.PgError
	if deleted != 1 || !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Fatalf("failed checkpoint=(%d, %v), want committed deletion and check violation", deleted, err)
	}
	if got := readCleanCheckpoint(t, ctx, db); got != before {
		t.Fatalf("failed save changed durable checkpoint: %+v, want %+v", got, before)
	}
	if _, err := db.Exec(ctx, db.Pfx(`ALTER TABLE CERTDB_cert_cleanup DROP CONSTRAINT reject_checkpoint`)); err != nil {
		t.Fatal(err)
	}
	if deleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil || deleted != 0 {
		t.Fatalf("retry completed checkpoint=(%d, %v), want (0, nil)", deleted, err)
	}
	saved := readCleanCheckpoint(t, ctx, db)
	if saved.end != 0 || !saved.completed.Valid {
		t.Fatalf("completed checkpoint=%+v", saved)
	}
	// A later expiry cutoff does not bypass the persisted completed-sweep pause.
	later := cutoff.Add(2 * time.Hour)
	restarted := reopenCleanCheckpointDB(t, ctx, cs)
	if deleted, err := restarted.DeleteCertificates(ctx, later, 10); err != nil || deleted != 0 {
		t.Fatalf("restart during pause=(%d, %v), want (0, nil)", deleted, err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`UPDATE CERTDB_cert_cleanup SET completed_at=$1 WHERE id=1`), time.Now().Add(-2*CleanResetInterval)); err != nil {
		t.Fatal(err)
	}
	next := reopenCleanCheckpointDB(t, ctx, cs)
	if deleted, err := next.DeleteCertificates(ctx, later, 10); err != nil || deleted != 1 {
		t.Fatalf("next sweep=(%d, %v), want later-expiring certificate removed", deleted, err)
	}
}
