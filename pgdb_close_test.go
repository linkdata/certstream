package certstream_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPgDB_Close_WaitsForExportedCall(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if db, err := newPgDBFromConnWithConns(ctx, conn, 2); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})
		if identID, err := defaultIdentID(ctx, db, db.Pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
			notBefore := now.Add(-30 * 24 * time.Hour)
			if certID, err := insertTestCertWithEntry(ctx, db, streamID, identID, 1, notBefore, now.Add(-5*24*time.Hour), testSHA256Hex(11)); err != nil {
				t.Fatalf("insert test cert failed: %v", err)
			} else {
				if tx, err := conn.Begin(ctx); err != nil {
					t.Fatalf("begin lock transaction failed: %v", err)
				} else {
					if _, err = tx.Exec(ctx, db.Pfx(`LOCK TABLE CERTDB_cert IN ACCESS EXCLUSIVE MODE;`)); err != nil {
						_ = tx.Rollback(ctx)
						t.Fatalf("lock table failed: %v", err)
					} else {
						callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
						t.Cleanup(cancel)
						queryDone := make(chan error, 1)
						go func() {
							_, queryErr := db.GetCertificateByID(callCtx, certID)
							queryDone <- queryErr
						}()

						deadline := time.Now().Add(2 * time.Second)
						for time.Now().Before(deadline) && db.Stat().AcquiredConns() == 0 {
							time.Sleep(10 * time.Millisecond)
						}
						if db.Stat().AcquiredConns() == 0 {
							_ = tx.Rollback(ctx)
							t.Fatal("timed out waiting for blocked query to acquire pooled connection")
						} else {
							closeDone := make(chan struct{})
							go func() {
								db.Close()
								close(closeDone)
							}()

							select {
							case <-closeDone:
								_ = tx.Rollback(ctx)
								t.Fatal("Close returned while exported call was in-flight")
							case <-time.After(200 * time.Millisecond):
							}

							if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
								t.Fatalf("unlock transaction failed: %v", rollbackErr)
							} else {
								select {
								case queryErr := <-queryDone:
									if queryErr != nil {
										t.Fatalf("GetCertificateByID failed: %v", queryErr)
									}
								case <-time.After(5 * time.Second):
									t.Fatal("timed out waiting for blocked query to complete")
								}
								select {
								case <-closeDone:
								case <-time.After(5 * time.Second):
									t.Fatal("timed out waiting for Close to return")
								}
							}
						}
					}
				}
			}
		}
	}
}
