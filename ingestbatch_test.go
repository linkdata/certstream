package certstream_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linkdata/certstream"
)

const ingestSha256Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var (
	ingestNotBefore = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ingestNotAfter  = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
)

func ingestRow(streamID int32, logIndex int64, dnsnames string, seen time.Time) map[string]any {
	return map[string]any{
		"iss_org":     "Issuer Org",
		"iss_prov":    "CA",
		"iss_country": "US",
		"sub_org":     "Subject Org",
		"sub_prov":    "CA",
		"sub_country": "US",
		"commonname":  "example.com",
		"notbefore":   ingestNotBefore,
		"notafter":    ingestNotAfter,
		"sha256_hex":  ingestSha256Hex,
		"precert":     false,
		"seen":        seen,
		"stream":      streamID,
		"logindex":    logIndex,
		"dnsnames":    dnsnames,
		"ipaddrs":     "",
		"emails":      "",
		"uris":        "",
	}
}

func callIngestBatch(ctx context.Context, conn *pgx.Conn, rows ...map[string]any) (err error) {
	var payload []byte
	if payload, err = json.Marshal(rows); err == nil {
		_, err = conn.Exec(ctx, "SELECT CERTDB_ingest_batch($1::jsonb);", string(payload))
	}
	return
}

func ingestCounts(ctx context.Context, conn *pgx.Conn) (certCount, entryCount, domainCount int, err error) {
	if conn != nil {
		err = conn.QueryRow(ctx, "SELECT COUNT(*) FROM CERTDB_cert;").Scan(&certCount)
		if err == nil {
			err = conn.QueryRow(ctx, "SELECT COUNT(*) FROM CERTDB_entry;").Scan(&entryCount)
			if err == nil {
				err = conn.QueryRow(ctx, "SELECT COUNT(*) FROM CERTDB_domain;").Scan(&domainCount)
			}
		}
	}
	return
}

func setupIngestBatchTest(t *testing.T) (ctx context.Context, conn *pgx.Conn, streamID int32) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH; skipping Postgres container portion")
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Minute)
		t.Cleanup(cancel)

		cname := "certstream-ingest-" + randHex(6)
		if out, err := run(ctx, "docker", "pull", pgImage); err != nil {
			t.Fatalf("docker pull %s failed: %v\n%s", pgImage, err, out)
		} else {
			if out, err := run(ctx, "docker", "run", "--rm", "-d",
				"--name", cname,
				"-e", "POSTGRES_USER="+pgUser,
				"-e", "POSTGRES_PASSWORD="+pgPass,
				"-e", "POSTGRES_DB="+pgDB,
				"-P", pgImage); err != nil {
				t.Fatalf("docker run failed: %v\n%s", err, out)
			} else {
				t.Cleanup(func() {
					_, _ = run(context.Background(), "docker", "kill", cname)
				})

				hostPort := dockerMappedPort(ctx, t, cname, "5432/tcp")
				waitForPostgresQueryReady(ctx, t, cname, pgUser, pgPass, pgDB, 2*time.Minute)

				dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable", pgUser, pgPass, hostPort, pgDB)
				if conn, err = pgx.Connect(ctx, dsn); err != nil {
					t.Fatalf("pgx connect failed: %v", err)
				} else {
					t.Cleanup(func() {
						conn.Close(ctx)
					})

					if _, err = conn.Exec(ctx, certstream.CreateSchema); err != nil {
						t.Fatalf("CreateSchema failed: %v", err)
					} else {
						if _, err = conn.Exec(ctx, certstream.FuncIngestBatch); err != nil {
							t.Fatalf("FuncIngestBatch failed: %v", err)
						} else {
							var operatorID int
							if err = conn.QueryRow(ctx,
								"INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id",
								"op", "op@example.com").Scan(&operatorID); err != nil {
								t.Fatalf("insert operator failed: %v", err)
							} else {
								if err = conn.QueryRow(ctx,
									"INSERT INTO CERTDB_stream (url, operator, json) VALUES ($1, $2, $3) RETURNING id",
									"https://example.com/log", operatorID, "{}").Scan(&streamID); err != nil {
									t.Fatalf("insert stream failed: %v", err)
								}
							}
						}
					}
				}
			}
		}
	}

	return
}

func TestIngestBatch_DedupCertificateAcrossCalls(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	firstSeen := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	if err := callIngestBatch(ctx, conn, ingestRow(streamID, 1, "example.com", firstSeen)); err != nil {
		t.Fatalf("first ingest batch failed: %v", err)
	} else {
		if certCount, entryCount, domainCount, err := ingestCounts(ctx, conn); err != nil {
			t.Fatalf("count after first ingest failed: %v", err)
		} else {
			if certCount != 1 {
				t.Fatalf("cert count after first ingest = %d, want 1", certCount)
			} else if entryCount != 1 {
				t.Fatalf("entry count after first ingest = %d, want 1", entryCount)
			} else if domainCount != 1 {
				t.Fatalf("domain count after first ingest = %d, want 1", domainCount)
			} else {
				secondSeen := firstSeen.Add(2 * time.Hour)
				if err = callIngestBatch(ctx, conn, ingestRow(streamID, 2, "example.com extra.example.com", secondSeen)); err != nil {
					t.Fatalf("second ingest batch failed: %v", err)
				} else {
					if certCount, entryCount, domainCount, err := ingestCounts(ctx, conn); err != nil {
						t.Fatalf("count after second ingest failed: %v", err)
					} else {
						if certCount != 1 {
							t.Fatalf("cert count after second ingest = %d, want 1", certCount)
						} else if entryCount != 2 {
							t.Fatalf("entry count after second ingest = %d, want 2", entryCount)
						} else if domainCount != 1 {
							t.Fatalf("domain count after second ingest = %d, want 1", domainCount)
						}
					}
				}
			}
		}
	}
}

func TestIngestBatch_DedupCertificateWithinBatch(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	firstSeen := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	secondSeen := firstSeen.Add(2 * time.Hour)
	firstRow := ingestRow(streamID, 1, "example.com", firstSeen)
	secondRow := ingestRow(streamID, 2, "example.com extra.example.com", secondSeen)

	if err := callIngestBatch(ctx, conn, firstRow, secondRow); err != nil {
		t.Fatalf("ingest batch failed: %v", err)
	} else {
		if certCount, entryCount, domainCount, err := ingestCounts(ctx, conn); err != nil {
			t.Fatalf("count after ingest failed: %v", err)
		} else {
			if certCount != 1 {
				t.Fatalf("cert count after ingest = %d, want 1", certCount)
			} else if entryCount != 2 {
				t.Fatalf("entry count after ingest = %d, want 2", entryCount)
			} else if domainCount != 1 {
				t.Fatalf("domain count after ingest = %d, want 1", domainCount)
			}
		}
	}
}
