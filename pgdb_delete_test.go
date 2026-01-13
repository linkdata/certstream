package certstream_test

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linkdata/certstream"
)

func newPgDBFromConn(ctx context.Context, conn *pgx.Conn) (db *certstream.PgDB, err error) {
	if conn != nil {
		pgCfg := conn.Config()
		addr := net.JoinHostPort(pgCfg.Host, strconv.Itoa(int(pgCfg.Port)))
		cfg := certstream.NewConfig()
		cfg.PgUser = pgCfg.User
		cfg.PgPass = pgCfg.Password
		cfg.PgName = pgCfg.Database
		cfg.PgAddr = addr
		cfg.PgNoSSL = true
		cs := &certstream.CertStream{Config: *cfg}
		db, err = certstream.NewPgDB(ctx, cs)
	}
	return
}

func defaultIdentID(ctx context.Context, db *certstream.PgDB) (id int, err error) {
	err = db.QueryRow(ctx, db.Pfx(`SELECT id FROM CERTDB_ident WHERE organization='' AND province='' AND country='';`)).Scan(&id)
	return
}

func insertTestCertWithEntry(ctx context.Context, db *certstream.PgDB, streamID int, identID int, logIndex int64, notBefore time.Time, notAfter time.Time, shaHex string) (certID int64, err error) {
	err = db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
VALUES ($1, $2, $3, $4, $5, $6, decode($7,'hex'), $8)
RETURNING id;`),
		notBefore, notAfter, notBefore, "example.com", identID, identID, shaHex, false,
	).Scan(&certID)
	if err == nil {
		_, err = db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (seen, cert, logindex, stream) VALUES ($1, $2, $3, $4);`),
			notAfter, certID, logIndex, streamID,
		)
	}
	return
}

func certEntryCounts(ctx context.Context, db *certstream.PgDB, certID int64) (certCount int, entryCount int, err error) {
	if certCount, err = countRows(ctx, db, `SELECT COUNT(*) FROM CERTDB_cert WHERE id=$1;`, certID); err == nil {
		entryCount, err = countRows(ctx, db, `SELECT COUNT(*) FROM CERTDB_entry WHERE cert=$1;`, certID)
	}
	return
}

func countRows(ctx context.Context, db *certstream.PgDB, query string, args ...any) (count int, err error) {
	err = db.QueryRow(ctx, db.Pfx(query), args...).Scan(&count)
	return
}

func testSHA256Hex(seed byte) string {
	buf := make([]byte, 32)
	buf[len(buf)-1] = seed
	return hex.EncodeToString(buf)
}

func TestPgDB_DeleteExpiredCert_BatchOrder(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if db, err := newPgDBFromConn(ctx, conn); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})

		if identID, err := defaultIdentID(ctx, db); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Now()
			notBefore := now.Add(-120 * time.Hour)
			type certFixture struct {
				name     string
				notAfter time.Time
				shaSeed  byte
				logIndex int64
			}
			fixtures := []certFixture{
				{name: "oldest", notAfter: now.Add(-72 * time.Hour), shaSeed: 1, logIndex: 1},
				{name: "old", notAfter: now.Add(-48 * time.Hour), shaSeed: 2, logIndex: 2},
				{name: "recent", notAfter: now.Add(-12 * time.Hour), shaSeed: 3, logIndex: 3},
				{name: "future", notAfter: now.Add(12 * time.Hour), shaSeed: 4, logIndex: 4},
			}
			ids := make(map[string]int64, len(fixtures))
			var err error
			for _, fixture := range fixtures {
				if err == nil {
					var certID int64
					certID, err = insertTestCertWithEntry(ctx, db, streamID, identID, fixture.logIndex, notBefore, fixture.notAfter, testSHA256Hex(fixture.shaSeed))
					ids[fixture.name] = certID
				}
			}
			if err != nil {
				t.Fatalf("insert test cert failed: %v", err)
			} else {
				if rowsDeleted, err := db.DeleteExpiredCert(ctx, 24*time.Hour, 1); err != nil {
					t.Fatalf("DeleteExpiredCert failed: %v", err)
				} else {
					if rowsDeleted != 1 {
						t.Fatalf("rows deleted = %d, want 1", rowsDeleted)
					} else {
						type expectedCount struct {
							name       string
							certCount  int
							entryCount int
						}
						expectFirst := []expectedCount{
							{name: "oldest", certCount: 0, entryCount: 1},
							{name: "old", certCount: 1, entryCount: 1},
							{name: "recent", certCount: 1, entryCount: 1},
							{name: "future", certCount: 1, entryCount: 1},
						}
						for _, exp := range expectFirst {
							if certCount, entryCount, err := certEntryCounts(ctx, db, ids[exp.name]); err != nil {
								t.Fatalf("count after first delete for %s failed: %v", exp.name, err)
							} else if certCount != exp.certCount {
								t.Fatalf("cert count after first delete for %s = %d, want %d", exp.name, certCount, exp.certCount)
							} else if entryCount != exp.entryCount {
								t.Fatalf("entry count after first delete for %s = %d, want %d", exp.name, entryCount, exp.entryCount)
							}
						}

						if rowsDeleted, err = db.DeleteExpiredCert(ctx, 24*time.Hour, 10); err != nil {
							t.Fatalf("second DeleteExpiredCert failed: %v", err)
						} else {
							if rowsDeleted != 1 {
								t.Fatalf("rows deleted second call = %d, want 1", rowsDeleted)
							} else {
								expectSecond := []expectedCount{
									{name: "old", certCount: 0, entryCount: 1},
									{name: "recent", certCount: 1, entryCount: 1},
									{name: "future", certCount: 1, entryCount: 1},
								}
								for _, exp := range expectSecond {
									if certCount, entryCount, err := certEntryCounts(ctx, db, ids[exp.name]); err != nil {
										t.Fatalf("count after second delete for %s failed: %v", exp.name, err)
									} else if certCount != exp.certCount {
										t.Fatalf("cert count after second delete for %s = %d, want %d", exp.name, certCount, exp.certCount)
									} else if entryCount != exp.entryCount {
										t.Fatalf("entry count after second delete for %s = %d, want %d", exp.name, entryCount, exp.entryCount)
									}
								}

								if rowsDeleted, err = db.DeleteExpiredCert(ctx, 24*time.Hour, 10); err != nil {
									t.Fatalf("third DeleteExpiredCert failed: %v", err)
								} else if rowsDeleted != 0 {
									t.Fatalf("rows deleted third call = %d, want 0", rowsDeleted)
								}
							}
						}
					}
				}
			}
		}
	}
}
