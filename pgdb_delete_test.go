package certstream_test

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/linkdata/certstream"
)

type queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type execQueryer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func newPgDBFromConn(ctx context.Context, conn *pgx.Conn) (db *certstream.PgDB, err error) {
	db, err = newPgDBFromConnWithConns(ctx, conn, 0)
	return
}

func newPgDBFromConnWithConns(ctx context.Context, conn *pgx.Conn, maxConns int) (db *certstream.PgDB, err error) {
	if conn != nil {
		pgCfg := conn.Config()
		addr := net.JoinHostPort(pgCfg.Host, strconv.Itoa(int(pgCfg.Port)))
		cfg := certstream.NewConfig()
		cfg.PgUser = pgCfg.User
		cfg.PgPass = pgCfg.Password
		cfg.PgName = pgCfg.Database
		cfg.PgAddr = addr
		cfg.PgNoSSL = true
		if maxConns > 0 {
			cfg.PgConns = maxConns
		}
		cs := &certstream.CertStream{Config: *cfg}
		db, err = certstream.NewPgDB(ctx, cs)
	}
	return
}

func defaultIdentID(ctx context.Context, q queryer, pfx func(string) string) (id int, err error) {
	err = q.QueryRow(ctx, pfx(`SELECT id FROM CERTDB_ident WHERE organization='' AND province='' AND country='';`)).Scan(&id)
	return
}

func insertTestCert(ctx context.Context, q execQueryer, pfx func(string) string, identID int, notBefore time.Time, notAfter time.Time, shaHex string) (certID int64, err error) {
	notBefore = notBefore.UTC()
	notAfter = notAfter.UTC()
	err = q.QueryRow(ctx, pfx(`INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
VALUES ($1, $2, $3, $4, $5, $6, decode($7,'hex'), $8)
RETURNING id;`),
		notBefore, notAfter, notBefore, "example.com", identID, identID, shaHex, false,
	).Scan(&certID)
	return
}

func insertTestEntry(ctx context.Context, q execQueryer, pfx func(string) string, certID int64, logIndex int64, streamID int32, seen time.Time) (err error) {
	seen = seen.UTC()
	_, err = q.Exec(ctx, pfx(`INSERT INTO CERTDB_entry (seen, cert, logindex, stream) VALUES ($1, $2, $3, $4);`),
		seen, certID, logIndex, streamID,
	)
	return
}

func insertTestCertWithEntry(ctx context.Context, db *certstream.PgDB, streamID int32, identID int, logIndex int64, notBefore time.Time, notAfter time.Time, shaHex string) (certID int64, err error) {
	if certID, err = insertTestCert(ctx, db, db.Pfx, identID, notBefore, notAfter, shaHex); err == nil {
		err = insertTestEntry(ctx, db, db.Pfx, certID, logIndex, streamID, notAfter)
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

func streamEntryCounts(ctx context.Context, db *certstream.PgDB, streamID int32) (streamCount int, entryCount int, err error) {
	if streamCount, err = countRows(ctx, db, `SELECT COUNT(*) FROM CERTDB_stream WHERE id=$1;`, streamID); err == nil {
		entryCount, err = countRows(ctx, db, `SELECT COUNT(*) FROM CERTDB_entry WHERE stream=$1;`, streamID)
	}
	return
}

func streamLogIndices(ctx context.Context, db *certstream.PgDB, streamID int32) (indices []int64, err error) {
	var rows pgx.Rows
	if rows, err = db.Query(ctx, db.Pfx(`SELECT logindex FROM CERTDB_entry WHERE stream=$1 ORDER BY logindex ASC;`), streamID); err == nil {
		defer rows.Close()
		for rows.Next() {
			var logIndex int64
			if err = rows.Scan(&logIndex); err == nil {
				indices = append(indices, logIndex)
			} else {
				break
			}
		}
		if err == nil {
			err = rows.Err()
		}
	}
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

		if identID, err := defaultIdentID(ctx, db, db.Pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Now().UTC()
			cutoff := now.Add(-24 * time.Hour)
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
				if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil {
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

						if rowsDeleted, err = db.DeleteCertificates(ctx, cutoff, 10); err != nil {
							t.Fatalf("second DeleteExpiredCert failed: %v", err)
						} else {
							if rowsDeleted != 1 {
								t.Fatalf("rows deleted second call = %d, want 1", rowsDeleted)
							} else {
								expectSecond := []expectedCount{
									{name: "oldest", certCount: 0, entryCount: 1},
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

								if rowsDeleted, err = db.DeleteCertificates(ctx, cutoff, 10); err != nil {
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

func TestPgDB_DeleteCertificates_ResumesAndRestarts(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if db, err := newPgDBFromConn(ctx, conn); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})

		if identID, err := defaultIdentID(ctx, db, db.Pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Now().UTC()
			cutoff := now.Add(-24 * time.Hour)
			notBefore := now.Add(-480 * time.Hour)

			for i, age := range []time.Duration{-72 * time.Hour, -48 * time.Hour} {
				if _, err := insertTestCertWithEntry(ctx, db, streamID, identID, int64(i+1), notBefore, now.Add(age), testSHA256Hex(byte(i+1))); err != nil {
					t.Fatalf("insert test cert failed: %v", err)
				}
			}

			// One per call, oldest first, leaving the cursor above both.
			for call := 1; call <= 2; call++ {
				if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 1); err != nil {
					t.Fatalf("DeleteCertificates call %d failed: %v", call, err)
				} else if rowsDeleted != 1 {
					t.Fatalf("rows deleted call %d = %d, want 1", call, rowsDeleted)
				}
			}

			// An empty batch restarts the cursor.
			if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil {
				t.Fatalf("draining DeleteCertificates failed: %v", err)
			} else if rowsDeleted != 0 {
				t.Fatalf("rows deleted when drained = %d, want 0", rowsDeleted)
			}

			// A certificate older than where the cursor stopped is still found.
			if certID, err := insertTestCertWithEntry(ctx, db, streamID, identID, 3, notBefore, now.Add(-96*time.Hour), testSHA256Hex(3)); err != nil {
				t.Fatalf("insert test cert failed: %v", err)
			} else if rowsDeleted, err := db.DeleteCertificates(ctx, cutoff, 10); err != nil {
				t.Fatalf("DeleteCertificates after restart failed: %v", err)
			} else if rowsDeleted != 1 {
				t.Fatalf("rows deleted after restart = %d, want 1", rowsDeleted)
			} else if certCount, _, err := certEntryCounts(ctx, db, certID); err != nil {
				t.Fatalf("count after restart failed: %v", err)
			} else if certCount != 0 {
				t.Fatalf("cert count after restart = %d, want 0", certCount)
			}
		}
	}
}

func TestPgDB_DeleteStream_BatchOrder(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if db, err := newPgDBFromConn(ctx, conn); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})

		if identID, err := defaultIdentID(ctx, db, db.Pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Now().UTC()
			notBefore := now.Add(-24 * time.Hour)
			notAfter := now.Add(24 * time.Hour)
			type fixture struct {
				logIndex int64
				shaSeed  byte
			}
			fixtures := []fixture{
				{logIndex: 5, shaSeed: 1},
				{logIndex: 2, shaSeed: 2},
				{logIndex: 9, shaSeed: 3},
			}
			var err error
			for _, fixture := range fixtures {
				if err == nil {
					_, err = insertTestCertWithEntry(ctx, db, streamID, identID, fixture.logIndex, notBefore, notAfter, testSHA256Hex(fixture.shaSeed))
				}
			}
			if err != nil {
				t.Fatalf("insert test cert failed: %v", err)
			} else {
				if rowsDeleted, err := db.DeleteStream(ctx, streamID, 2); err != nil {
					t.Fatalf("DeleteStream failed: %v", err)
				} else {
					if rowsDeleted != 2 {
						t.Fatalf("rows deleted = %d, want 2", rowsDeleted)
					} else {
						if indices, err := streamLogIndices(ctx, db, streamID); err != nil {
							t.Fatalf("log index lookup failed: %v", err)
						} else {
							expect := []int64{9}
							if len(indices) != len(expect) {
								t.Fatalf("remaining logindex count = %d, want %d", len(indices), len(expect))
							} else {
								for i := range expect {
									if indices[i] != expect[i] {
										t.Fatalf("remaining logindex[%d] = %d, want %d", i, indices[i], expect[i])
									}
								}
								if streamCount, entryCount, err := streamEntryCounts(ctx, db, streamID); err != nil {
									t.Fatalf("count after first delete failed: %v", err)
								} else if streamCount != 1 {
									t.Fatalf("stream count after first delete = %d, want 1", streamCount)
								} else if entryCount != 1 {
									t.Fatalf("entry count after first delete = %d, want 1", entryCount)
								} else {
									if rowsDeleted, err = db.DeleteStream(ctx, streamID, 2); err != nil {
										t.Fatalf("second DeleteStream failed: %v", err)
									} else {
										if rowsDeleted != 1 {
											t.Fatalf("rows deleted second call = %d, want 1", rowsDeleted)
										} else {
											if streamCount, entryCount, err = streamEntryCounts(ctx, db, streamID); err != nil {
												t.Fatalf("count after second delete failed: %v", err)
											} else if streamCount != 1 {
												t.Fatalf("stream count after second delete = %d, want 1", streamCount)
											} else if entryCount != 0 {
												t.Fatalf("entry count after second delete = %d, want 0", entryCount)
											} else {
												if rowsDeleted, err = db.DeleteStream(ctx, streamID, 2); err != nil {
													t.Fatalf("third DeleteStream failed: %v", err)
												} else {
													if rowsDeleted != 1 {
														t.Fatalf("rows deleted third call = %d, want 1", rowsDeleted)
													} else {
														if streamCount, entryCount, err = streamEntryCounts(ctx, db, streamID); err != nil {
															t.Fatalf("count after third delete failed: %v", err)
														} else if streamCount != 0 {
															t.Fatalf("stream count after third delete = %d, want 0", streamCount)
														} else if entryCount != 0 {
															t.Fatalf("entry count after third delete = %d, want 0", entryCount)
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestPgDB_DeleteStream_ResumesAndFindsBackfilled(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if db, err := newPgDBFromConn(ctx, conn); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})

		if identID, err := defaultIdentID(ctx, db, db.Pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Now().UTC()
			notBefore := now.Add(-24 * time.Hour)
			notAfter := now.Add(24 * time.Hour)

			for _, logIndex := range []int64{10, 11, 12} {
				if _, err := insertTestCertWithEntry(ctx, db, streamID, identID, logIndex, notBefore, notAfter, testSHA256Hex(byte(logIndex))); err != nil {
					t.Fatalf("insert entry %d failed: %v", logIndex, err)
				}
			}

			// Oldest first, leaving the cursor above logindex 11.
			if rowsDeleted, err := db.DeleteStream(ctx, streamID, 2); err != nil {
				t.Fatalf("DeleteStream failed: %v", err)
			} else if rowsDeleted != 2 {
				t.Fatalf("rows deleted = %d, want 2", rowsDeleted)
			} else if indices, err := streamLogIndices(ctx, db, streamID); err != nil {
				t.Fatalf("index listing failed: %v", err)
			} else if len(indices) != 1 || indices[0] != 12 {
				t.Fatalf("remaining indices = %v, want [12]", indices)
			}

			// Backfill an entry below where the cursor stopped.
			if _, err := insertTestCertWithEntry(ctx, db, streamID, identID, 1, notBefore, notAfter, testSHA256Hex(99)); err != nil {
				t.Fatalf("insert backfilled entry failed: %v", err)
			}

			// The cursor still clears what is above it.
			if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
				t.Fatalf("DeleteStream above cursor failed: %v", err)
			} else if rowsDeleted != 1 {
				t.Fatalf("rows deleted above cursor = %d, want 1", rowsDeleted)
			}

			// Reaching the end restarts the scan and finds the backfilled entry,
			// rather than dropping the stream while it still holds one.
			if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
				t.Fatalf("DeleteStream restart failed: %v", err)
			} else if rowsDeleted != 1 {
				t.Fatalf("rows deleted after restart = %d, want 1", rowsDeleted)
			} else if indices, err := streamLogIndices(ctx, db, streamID); err != nil {
				t.Fatalf("index listing failed: %v", err)
			} else if len(indices) != 0 {
				t.Fatalf("remaining indices = %v, want none", indices)
			}

			// Only now is the stream itself removed.
			if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
				t.Fatalf("DeleteStream on empty stream failed: %v", err)
			} else if rowsDeleted != 1 {
				t.Fatalf("rows deleted removing stream = %d, want 1", rowsDeleted)
			} else if count, err := countRows(ctx, db, `SELECT COUNT(*) FROM CERTDB_stream WHERE id=$1;`, streamID); err != nil {
				t.Fatalf("stream count failed: %v", err)
			} else if count != 0 {
				t.Fatalf("stream count = %d, want 0", count)
			}
		}
	}
}

func TestPgDB_DeleteStream_LockedEntriesKeepStream(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if db, err := newPgDBFromConn(ctx, conn); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})

		if identID, err := defaultIdentID(ctx, db, db.Pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Now().UTC()
			notBefore := now.Add(-24 * time.Hour)
			notAfter := now.Add(24 * time.Hour)
			for logIndex := int64(1); logIndex <= 5; logIndex++ {
				if _, err := insertTestCertWithEntry(ctx, db, streamID, identID, logIndex, notBefore, notAfter, testSHA256Hex(byte(logIndex))); err != nil {
					t.Fatalf("insert entry %d failed: %v", logIndex, err)
				}
			}

			// Hold every entry locked on a separate connection, so the batch
			// below skips all of them and comes back empty.
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatalf("begin failed: %v", err)
			}
			if _, err = tx.Exec(ctx, db.Pfx(`SELECT logindex FROM CERTDB_entry WHERE stream = $1 FOR UPDATE;`), streamID); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatalf("locking entries failed: %v", err)
			}

			// Bounded, because a version that tries to drop the stream here
			// blocks on those locks instead of returning: the cascade has to
			// delete the very rows the transaction above is holding.
			lockedCtx, cancelLocked := context.WithTimeout(ctx, 10*time.Second)
			defer cancelLocked()
			if rowsDeleted, err := db.DeleteStream(lockedCtx, streamID, 1); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatalf("DeleteStream failed: %v", err)
			} else if rowsDeleted != 0 {
				_ = tx.Rollback(ctx)
				t.Fatalf("rows deleted with everything locked = %d, want 0", rowsDeleted)
			}

			// The stream and its entries must both survive: an empty batch only
			// means nothing unlocked was found.
			if streamCount, entryCount, err := streamEntryCounts(ctx, db, streamID); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatalf("counts failed: %v", err)
			} else if streamCount != 1 {
				_ = tx.Rollback(ctx)
				t.Fatalf("stream count = %d, want 1", streamCount)
			} else if entryCount != 5 {
				_ = tx.Rollback(ctx)
				t.Fatalf("entry count = %d, want 5", entryCount)
			}

			if err = tx.Rollback(ctx); err != nil {
				t.Fatalf("rollback failed: %v", err)
			}

			// Once the locks are gone the stream drains and is removed.
			for range 10 {
				if rowsDeleted, err := db.DeleteStream(ctx, streamID, 10); err != nil {
					t.Fatalf("DeleteStream after unlock failed: %v", err)
				} else if rowsDeleted == 0 {
					break
				}
			}
			if streamCount, entryCount, err := streamEntryCounts(ctx, db, streamID); err != nil {
				t.Fatalf("counts failed: %v", err)
			} else if streamCount != 0 || entryCount != 0 {
				t.Fatalf("after unlock stream=%d entries=%d, want 0 and 0", streamCount, entryCount)
			}
		}
	}
}

func TestPgDB_DeleteStream_NoEntriesDeletesStream(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if db, err := newPgDBFromConn(ctx, conn); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	} else {
		t.Cleanup(func() {
			db.Close()
		})

		if streamCount, entryCount, err := streamEntryCounts(ctx, db, streamID); err != nil {
			t.Fatalf("initial count failed: %v", err)
		} else if streamCount != 1 {
			t.Fatalf("initial stream count = %d, want 1", streamCount)
		} else if entryCount != 0 {
			t.Fatalf("initial entry count = %d, want 0", entryCount)
		} else {
			if rowsDeleted, err := db.DeleteStream(ctx, streamID, 3); err != nil {
				t.Fatalf("DeleteStream failed: %v", err)
			} else {
				if rowsDeleted != 1 {
					t.Fatalf("rows deleted = %d, want 1", rowsDeleted)
				} else {
					if streamCount, entryCount, err = streamEntryCounts(ctx, db, streamID); err != nil {
						t.Fatalf("final count failed: %v", err)
					} else if streamCount != 0 {
						t.Fatalf("final stream count = %d, want 0", streamCount)
					} else if entryCount != 0 {
						t.Fatalf("final entry count = %d, want 0", entryCount)
					}
				}
			}
		}
	}
}

func TestPgDB_TimestampsUseUTC(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	pfx := func(s string) string { return s }
	if _, err := conn.Exec(ctx, "SET TIME ZONE INTERVAL '-07:00';"); err != nil {
		t.Fatalf("set time zone failed: %v", err)
	} else {
		if identID, err := defaultIdentID(ctx, conn, pfx); err != nil {
			t.Fatalf("default ident lookup failed: %v", err)
		} else {
			now := time.Now().UTC()
			notBefore := now.Add(-24 * time.Hour)
			notAfter := now.Add(24 * time.Hour)
			if certID, err := insertTestCert(ctx, conn, pfx, identID, notBefore, notAfter, testSHA256Hex(5)); err != nil {
				t.Fatalf("insert test cert failed: %v", err)
			} else {
				if _, err = conn.Exec(ctx, pfx(`INSERT INTO CERTDB_domain (cert, wild, www, domain, tld) VALUES ($1, $2, $3, $4, $5);`),
					certID, false, 0, "example", "com",
				); err != nil {
					t.Fatalf("insert domain failed: %v", err)
				} else {
					var valid bool
					if err = conn.QueryRow(ctx, pfx(`SELECT valid FROM CERTDB_dnsnames WHERE cert=$1 LIMIT 1;`), certID).Scan(&valid); err != nil {
						t.Fatalf("select valid failed: %v", err)
					} else if !valid {
						t.Fatalf("valid = false, want true")
					} else {
						var delta float64
						if err = conn.QueryRow(ctx, pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream) VALUES ($1, $2, $3)
RETURNING ABS(EXTRACT(EPOCH FROM seen AT TIME ZONE 'UTC') - EXTRACT(EPOCH FROM NOW() AT TIME ZONE 'UTC'));`),
							certID, int64(1), streamID,
						).Scan(&delta); err != nil {
							t.Fatalf("insert entry failed: %v", err)
						} else if delta > 2 {
							t.Fatalf("UTC delta = %.2f, want <= 2", delta)
						}
					}
				}
			}
		}
	}
}
