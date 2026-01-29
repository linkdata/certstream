package certstream_test

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linkdata/certstream"
)

const (
	subdomainSha256Hex    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	subdomainSha256HexAlt = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func setupSubdomainTest(t *testing.T) (ctx context.Context, conn *pgx.Conn) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH; skipping Postgres container portion")
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(t.Context(), 3*time.Minute)
		t.Cleanup(cancel)

		cname := "certstream-subdomain-" + randHex(6)
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
					_, _ = run(t.Context(), "docker", "kill", cname)
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
						if _, err = conn.Exec(ctx, certstream.FuncSubdomain); err != nil {
							t.Fatalf("FuncSubdomain failed: %v", err)
						}
					}
				}
			}
		}
	}

	return
}

func TestSubdomainLatestCertificate(t *testing.T) {
	t.Parallel()

	ctx, conn := setupSubdomainTest(t)
	if conn != nil {
		var subjectID int
		var issuerID int
		if err := conn.QueryRow(ctx,
			"INSERT INTO CERTDB_ident (organization, province, country) VALUES ($1, $2, $3) RETURNING id;",
			"Subject Org", "CA", "US").Scan(&subjectID); err != nil {
			t.Fatalf("insert subject failed: %v", err)
		} else {
			if err = conn.QueryRow(ctx,
				"INSERT INTO CERTDB_ident (organization, province, country) VALUES ($1, $2, $3) RETURNING id;",
				"Issuer Org", "CA", "US").Scan(&issuerID); err != nil {
				t.Fatalf("insert issuer failed: %v", err)
			} else {
				chainSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
				firstNotBefore := chainSince
				firstNotAfter := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
				secondNotBefore := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
				secondNotAfter := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

				var firstCertID int64
				if err = conn.QueryRow(ctx, `
INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
VALUES ($1, $2, $3, $4, $5, $6, decode($7, 'hex'), $8)
RETURNING id;`,
					firstNotBefore,
					firstNotAfter,
					chainSince,
					"example.com",
					subjectID,
					issuerID,
					subdomainSha256Hex,
					false).Scan(&firstCertID); err != nil {
					t.Fatalf("insert first cert failed: %v", err)
				} else {
					if _, err = conn.Exec(ctx,
						"INSERT INTO CERTDB_domain (cert, wild, www, domain, tld) VALUES ($1, $2, $3, $4, $5);",
						firstCertID, false, 0, "foo.example", "com"); err != nil {
						t.Fatalf("insert first cert foo domain failed: %v", err)
					} else {
						if _, err = conn.Exec(ctx,
							"INSERT INTO CERTDB_domain (cert, wild, www, domain, tld) VALUES ($1, $2, $3, $4, $5);",
							firstCertID, false, 0, "bar.example", "com"); err != nil {
							t.Fatalf("insert first cert bar domain failed: %v", err)
						} else {
							var secondCertID int64
							if err = conn.QueryRow(ctx, `
INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
VALUES ($1, $2, $3, $4, $5, $6, decode($7, 'hex'), $8)
RETURNING id;`,
								secondNotBefore,
								secondNotAfter,
								chainSince,
								"example.com",
								subjectID,
								issuerID,
								subdomainSha256HexAlt,
								true).Scan(&secondCertID); err != nil {
								t.Fatalf("insert second cert failed: %v", err)
							} else {
								if _, err = conn.Exec(ctx,
									"INSERT INTO CERTDB_domain (cert, wild, www, domain, tld) VALUES ($1, $2, $3, $4, $5);",
									secondCertID, false, 0, "foo.example", "com"); err != nil {
									t.Fatalf("insert second cert foo domain failed: %v", err)
								} else {
									if _, err = conn.Exec(ctx,
										"INSERT INTO CERTDB_domain (cert, wild, www, domain, tld) VALUES ($1, $2, $3, $4, $5);",
										secondCertID, true, 1, "foo.example", "com"); err != nil {
										t.Fatalf("insert second cert foo domain duplicate failed: %v", err)
									} else {
										rows, err := conn.Query(ctx, `
SELECT subdomain, wild, www, tld, issuer, subject, notbefore, notafter, since, sha256, precert
FROM CERTDB_subdomain($1, $2);`, "elpmaxe", "com")
										if err != nil {
											t.Fatalf("query subdomain failed: %v", err)
										} else {
											if rows != nil {
												defer rows.Close()
											}

											type result struct {
												subdomain string
												wild      bool
												www       int16
												tld       string
												issuer    string
												subject   string
												notbefore time.Time
												notafter  time.Time
												since     time.Time
												sha256    string
												precert   bool
											}

											var results []result
											for rows.Next() {
												var r result
												if err = rows.Scan(
													&r.subdomain,
													&r.wild,
													&r.www,
													&r.tld,
													&r.issuer,
													&r.subject,
													&r.notbefore,
													&r.notafter,
													&r.since,
													&r.sha256,
													&r.precert,
												); err != nil {
													t.Fatalf("scan subdomain row failed: %v", err)
												} else {
													results = append(results, r)
												}
											}

											if err = rows.Err(); err != nil {
												t.Fatalf("subdomain rows error: %v", err)
											} else {
												if len(results) != 2 {
													t.Fatalf("subdomain rows = %d, want 2", len(results))
												} else {
													var sawPlain bool
													var sawWild bool
													for _, got := range results {
														if got.subdomain != "foo." {
															t.Fatalf("subdomain = %q, want %q", got.subdomain, "foo.")
														} else if got.tld != "com" {
															t.Fatalf("tld = %q, want %q", got.tld, "com")
														} else if got.issuer != "Issuer Org" {
															t.Fatalf("issuer = %q, want %q", got.issuer, "Issuer Org")
														} else if got.subject != "Subject Org" {
															t.Fatalf("subject = %q, want %q", got.subject, "Subject Org")
														} else if got.notbefore.Format(ingestTimestampFmt) != secondNotBefore.Format(ingestTimestampFmt) {
															t.Fatalf("notbefore = %s, want %s", got.notbefore.Format(ingestTimestampFmt), secondNotBefore.Format(ingestTimestampFmt))
														} else if got.notafter.Format(ingestTimestampFmt) != secondNotAfter.Format(ingestTimestampFmt) {
															t.Fatalf("notafter = %s, want %s", got.notafter.Format(ingestTimestampFmt), secondNotAfter.Format(ingestTimestampFmt))
														} else if got.since.Format(ingestTimestampFmt) != chainSince.Format(ingestTimestampFmt) {
															t.Fatalf("since = %s, want %s", got.since.Format(ingestTimestampFmt), chainSince.Format(ingestTimestampFmt))
														} else if got.sha256 != subdomainSha256HexAlt {
															t.Fatalf("sha256 = %q, want %q", got.sha256, subdomainSha256HexAlt)
														} else if got.precert != true {
															t.Fatalf("precert = %v, want true", got.precert)
														} else if got.wild && got.www == 1 {
															sawWild = true
														} else if !got.wild && got.www == 0 {
															sawPlain = true
														} else {
															t.Fatalf("wild/www = %v/%d, want {false/0,true/1}", got.wild, got.www)
														}
													}

													if !sawPlain || !sawWild {
														t.Fatalf("wild/www rows missing, saw plain=%v wild=%v", sawPlain, sawWild)
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
