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

const (
	ingestSha256Hex    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ingestSha256HexAlt = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

var (
	ingestNotBefore = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ingestNotAfter  = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
)

func ingestRow(streamID int32, logIndex int64, dnsnames string, seen time.Time) map[string]any {
	return ingestRowWithSHA(streamID, logIndex, dnsnames, seen, ingestSha256Hex)
}

func ingestRowWithSHA(streamID int32, logIndex int64, dnsnames string, seen time.Time, sha256Hex string) map[string]any {
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
		"sha256_hex":  sha256Hex,
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

func setupSplitDomainCallTracker(ctx context.Context, conn *pgx.Conn) (err error) {
	if conn != nil {
		if _, err = conn.Exec(ctx, `
CREATE TEMP TABLE certdb_split_domain_calls (
	fqdn text PRIMARY KEY,
	calls integer NOT NULL
);`); err == nil {
			if _, err = conn.Exec(ctx, "ALTER FUNCTION CERTDB_split_domain(text) RENAME TO CERTDB_split_domain_impl;"); err == nil {
				_, err = conn.Exec(ctx, `
CREATE OR REPLACE FUNCTION CERTDB_split_domain(_fqdn text)
RETURNS TABLE(wild boolean, www smallint, domain text, tld text)
LANGUAGE plpgsql
AS $$
BEGIN
	INSERT INTO certdb_split_domain_calls (fqdn, calls)
	VALUES (_fqdn, 1)
	ON CONFLICT (fqdn) DO UPDATE
	SET calls = certdb_split_domain_calls.calls + 1;

	RETURN QUERY
	SELECT s.wild, s.www, s.domain, s.tld
	FROM CERTDB_split_domain_impl(_fqdn) AS s;
END;
$$;`)
			}
		}
	}
	return
}

func splitDomainCallCount(ctx context.Context, conn *pgx.Conn, fqdn string) (calls int, err error) {
	if conn != nil {
		err = conn.QueryRow(ctx, "SELECT calls FROM certdb_split_domain_calls WHERE fqdn = $1;", fqdn).Scan(&calls)
	}
	return
}

func splitDomainCallTotal(ctx context.Context, conn *pgx.Conn) (total int, err error) {
	if conn != nil {
		err = conn.QueryRow(ctx, "SELECT COUNT(*) FROM certdb_split_domain_calls;").Scan(&total)
	}
	return
}

func assertSplitDomainCallCount(t *testing.T, ctx context.Context, conn *pgx.Conn, fqdn string, want int) {
	t.Helper()

	var calls int
	var err error
	if calls, err = splitDomainCallCount(ctx, conn, fqdn); err != nil {
		t.Fatalf("split domain call count for %s failed: %v", fqdn, err)
	} else if calls != want {
		t.Fatalf("split domain call count for %s = %d, want %d", fqdn, calls, want)
	}
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
							var operatorID int32
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

func TestIngestBatch_SplitDomainOncePerFQDN(t *testing.T) {
	t.Parallel()

	ctx, conn, streamID := setupIngestBatchTest(t)
	if err := setupSplitDomainCallTracker(ctx, conn); err != nil {
		t.Fatalf("setup split domain tracker failed: %v", err)
	} else {
		firstSeen := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
		secondSeen := firstSeen.Add(2 * time.Hour)
		firstRow := ingestRowWithSHA(streamID, 1, "shared.example.com unique-one.example.com", firstSeen, ingestSha256Hex)
		secondRow := ingestRowWithSHA(streamID, 2, "shared.example.com unique-two.example.com", secondSeen, ingestSha256HexAlt)

		if err = callIngestBatch(ctx, conn, firstRow, secondRow); err != nil {
			t.Fatalf("ingest batch failed: %v", err)
		} else {
			var totalCalls int
			if totalCalls, err = splitDomainCallTotal(ctx, conn); err != nil {
				t.Fatalf("split domain total calls failed: %v", err)
			} else if totalCalls != 3 {
				t.Fatalf("split domain total calls = %d, want 3", totalCalls)
			} else {
				assertSplitDomainCallCount(t, ctx, conn, "shared.example.com", 1)
				assertSplitDomainCallCount(t, ctx, conn, "unique-one.example.com", 1)
				assertSplitDomainCallCount(t, ctx, conn, "unique-two.example.com", 1)
			}
		}
	}
}
