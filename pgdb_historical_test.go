package certstream_test

import (
	"context"
	"testing"
	"time"

	"github.com/linkdata/certstream"
)

func TestPgDB_GetHistoricalCertificates_ClosesRowsBeforeCallback(t *testing.T) {
	t.Parallel()

	ctx, conn, _ := setupIngestBatchTest(t)
	if db, err := newPgDBFromConnWithConns(ctx, conn, 1); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})

		if identID, err := defaultIdentID(ctx, db, db.Pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
			notBefore := now.Add(-30 * 24 * time.Hour)
			if _, err = insertTestCert(ctx, db, db.Pfx, identID, notBefore, now.Add(-20*24*time.Hour), testSHA256Hex(1)); err != nil {
				t.Fatalf("insert test cert 1 failed: %v", err)
			} else if _, err = insertTestCert(ctx, db, db.Pfx, identID, notBefore, now.Add(-10*24*time.Hour), testSHA256Hex(2)); err != nil {
				t.Fatalf("insert test cert 2 failed: %v", err)
			} else {
				callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				t.Cleanup(cancel)

				count := 0
				if err = db.GetHistoricalCertificates(callCtx, now.Add(-40*24*time.Hour), func(ctx context.Context, cert *certstream.JsonCertificate) (err error) {
					if cert != nil {
						count++
					}
					return
				}); err != nil {
					t.Fatalf("GetHistoricalCertificates failed: %v", err)
				} else if count != 2 {
					t.Fatalf("cert count = %d, want 2", count)
				}
			}
		}
	}
}
