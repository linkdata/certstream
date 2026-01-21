package certstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

const (
	pgImage = "postgres:16-alpine"
	pgUser  = "cert"
	pgPass  = "secretpass"
	pgDB    = "certstream"
	pgPort  = "5432"
)

func TestPgDB_SelectAllGapsPerStream(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			urlA := "https://example.com/log-a"
			urlB := "https://example.com/log-b"
			var streamA int32
			if err = insertStream(ctx, db, urlA, operatorID, &streamA); err != nil {
				t.Fatalf("insert stream A failed: %v", err)
			} else {
				var streamB int32
				if err = insertStream(ctx, db, urlB, operatorID, &streamB); err != nil {
					t.Fatalf("insert stream B failed: %v", err)
				} else {
					if err = insertEntries(ctx, db, streamA, []int64{1, 2, 5, 6}); err != nil {
						t.Fatalf("insert entries stream A failed: %v", err)
					} else if err = insertEntries(ctx, db, streamB, []int64{10, 12, 13}); err != nil {
						t.Fatalf("insert entries stream B failed: %v", err)
					} else {
						logop := &LogOperator{
							CertStream: cs,
							operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
							Domain:     "example.com",
							streams:    map[string]*LogStream{},
						}
						lsA := &LogStream{
							LogOperator: logop,
							Id:          streamA,
							log:         &loglist3.Log{URL: urlA},
						}
						lsB := &LogStream{
							LogOperator: logop,
							Id:          streamB,
							log:         &loglist3.Log{URL: urlB},
						}
						lsA.gapCh = make(chan gap, 10)
						lsB.gapCh = make(chan gap, 10)
						logop.streams[urlA] = lsA
						logop.streams[urlB] = lsB
						cs.operators = map[string]*LogOperator{
							logop.Domain: logop,
						}
						chA := lsA.gapCh
						chB := lsB.gapCh

						var wg sync.WaitGroup
						wg.Add(1)
						go db.selectAllGaps(ctx, &wg)

						wg.Wait()
						if chA == nil || chB == nil {
							t.Fatalf("gap channel not initialized")
						} else {
							gotA := collectGaps(chA)
							gotB := collectGaps(chB)
							wantA := []gap{{start: 3, end: 4}}
							wantB := []gap{{start: 11, end: 11}}
							if !gapsEqual(gotA, wantA) {
								t.Fatalf("stream A gaps = %v, want %v", gotA, wantA)
							} else if !gapsEqual(gotB, wantB) {
								t.Fatalf("stream B gaps = %v, want %v", gotB, wantB)
							}
						}
					}
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsOrder(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-order"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else {
				if err = insertEntries(ctx, db, streamID, []int64{1, 2, 4, 7, 8, 11}); err != nil {
					t.Fatalf("insert entries failed: %v", err)
				} else {
					logop := &LogOperator{
						CertStream: cs,
						operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
						Domain:     "example.com",
						streams:    map[string]*LogStream{},
					}
					ls := &LogStream{
						LogOperator: logop,
						Id:          streamID,
						log:         &loglist3.Log{URL: url},
					}
					ls.gapCh = make(chan gap, 1)
					logop.streams[url] = ls
					cs.operators = map[string]*LogOperator{
						logop.Domain: logop,
					}

					addGapQuerySleep(t, db, "0.2")

					var wg sync.WaitGroup
					gotCh := make(chan []gap, 1)
					go func() {
						time.Sleep(300 * time.Millisecond)
						gotCh <- collectGaps(ls.gapCh)
					}()

					wg.Add(1)
					go db.selectStreamGaps(ctx, &wg, ls, 4, nil)

					wg.Wait()
					close(ls.gapCh)
					got := <-gotCh
					want := []gap{
						{start: 3, end: 3},
						{start: 5, end: 6},
						{start: 9, end: 10},
					}
					if !gapsEqual(got, want) {
						t.Fatalf("gaps = %v, want %v", got, want)
					}
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsMaxAtStart(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-max-at-start"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else {
				if err = insertEntries(ctx, db, streamID, []int64{1, 2, 4, 7, 8, 11}); err != nil {
					t.Fatalf("insert entries failed: %v", err)
				} else {
					logop := &LogOperator{
						CertStream: cs,
						operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
						Domain:     "example.com",
						streams:    map[string]*LogStream{},
					}
					ls := &LogStream{
						LogOperator: logop,
						Id:          streamID,
						log:         &loglist3.Log{URL: url},
					}
					ls.gapCh = make(chan gap, 10)
					logop.streams[url] = ls
					cs.operators = map[string]*LogOperator{
						logop.Domain: logop,
					}

					addGapQuerySleep(t, db, "0.2")

					firstGapCh := make(chan gap, 1)
					gotCh := make(chan []gap, 1)
					go func() {
						var got []gap
						for g := range ls.gapCh {
							if len(got) == 0 {
								firstGapCh <- g
							}
							got = append(got, g)
						}
						gotCh <- got
					}()

					var wg sync.WaitGroup
					wg.Add(1)
					go db.selectStreamGaps(ctx, &wg, ls, 4, nil)

					select {
					case <-firstGapCh:
						if err = insertEntries(ctx, db, streamID, []int64{20}); err != nil {
							t.Fatalf("insert entries after start failed: %v", err)
						} else {
							wg.Wait()
							close(ls.gapCh)
							got := <-gotCh
							want := []gap{
								{start: 3, end: 3},
								{start: 5, end: 6},
								{start: 9, end: 10},
							}
							if !gapsEqual(got, want) {
								t.Fatalf("gaps = %v, want %v", got, want)
							}
						}
					case <-time.After(2 * time.Second):
						t.Fatalf("timed out waiting for first gap")
					}
				}
			}
		}
	}
}

func setupSelectGapsDB(t *testing.T) (ctx context.Context, db *PgDB, cs *CertStream) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH; skipping Postgres container portion")
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Minute)
		t.Cleanup(cancel)

		cname := "certstream-gaps-" + randHex(6)
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

				cfg := NewConfig()
				cfg.PgUser = pgUser
				cfg.PgPass = pgPass
				cfg.PgName = pgDB
				cfg.PgAddr = "127.0.0.1:" + hostPort
				cfg.PgNoSSL = true
				cfg.PgConns = 4

				cs = &CertStream{
					Config:    *cfg,
					operators: map[string]*LogOperator{},
				}
				if db, err = NewPgDB(ctx, cs); err != nil {
					t.Fatalf("NewPgDB failed: %v", err)
				} else {
					cs.db = db
					t.Cleanup(func() {
						db.Close()
					})
				}
			}
		}
	}

	return
}

func insertStream(ctx context.Context, db *PgDB, url string, operatorID int32, streamID *int32) (err error) {
	if streamID != nil {
		err = db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_stream (url, operator, json) VALUES ($1, $2, $3) RETURNING id;`),
			url, operatorID, "{}",
		).Scan(streamID)
	}
	return
}

func insertEntries(ctx context.Context, db *PgDB, streamID int32, indices []int64) (err error) {
	for _, logIndex := range indices {
		if err == nil {
			_, err = db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream) VALUES ($1, $2, $3);`),
				logIndex+1000, logIndex, streamID,
			)
		}
	}
	return
}

func addGapQuerySleep(t *testing.T, db *PgDB, seconds string) {
	t.Helper()

	if db == nil {
		t.Fatalf("db is nil")
	} else {
		if !strings.Contains(db.stmtSelectAllGaps, "WITH findgap_seed") {
			t.Fatalf("selectAllGaps missing WITH findgap_seed")
		} else {
			db.stmtSelectAllGaps = strings.Replace(db.stmtSelectAllGaps,
				"WITH findgap_seed",
				"WITH gap_sleep AS (SELECT pg_sleep("+seconds+")),\nfindgap_seed",
				1,
			)
		}
		if !strings.Contains(db.stmtSelectAllGaps, "FROM last") {
			t.Fatalf("selectAllGaps missing FROM last")
		} else {
			db.stmtSelectAllGaps = strings.Replace(db.stmtSelectAllGaps,
				"FROM last",
				"FROM gap_sleep, last",
				1,
			)
		}
	}
}

func collectGaps(ch chan gap) (gaps []gap) {
	if ch != nil {
		for g := range ch {
			gaps = append(gaps, g)
		}
	}
	return
}

func gapsEqual(got []gap, want []gap) (equal bool) {
	if len(got) == len(want) {
		equal = true
		for i := range got {
			if got[i] != want[i] {
				equal = false
				break
			}
		}
	}
	return
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func dockerMappedPort(ctx context.Context, t *testing.T, cname, containerPort string) string {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		out, err := run(ctx, "docker", "port", cname, containerPort)
		if err == nil {
			lines := strings.SplitSeq(strings.TrimSpace(string(out)), "\n")
			for ln := range lines {
				if idx := strings.LastIndex(ln, ":"); idx > 0 && idx < len(ln)-1 {
					return strings.TrimSpace(ln[idx+1:])
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out resolving mapped port for %s", containerPort)
	return ""
}

func waitForPostgresQueryReady(ctx context.Context, t *testing.T, cname, user, pass, dbname string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastOut []byte
	var lastErr error

	for time.Now().Before(deadline) {
		out1, err1 := run(ctx, "docker", "exec", cname,
			"pg_isready", "-h", "127.0.0.1", "-p", pgPort, "-U", user, "-d", dbname,
		)
		if err1 == nil && bytes.Contains(out1, []byte("accepting connections")) {
			out2, err2 := run(ctx, "docker", "exec",
				"-e", "PGPASSWORD="+pass, cname,
				"psql", "-h", "127.0.0.1", "-p", pgPort, "-U", user, "-d", dbname,
				"-tAc", "SELECT 1",
			)
			if err2 == nil && bytes.Equal(bytes.TrimSpace(out2), []byte("1")) {
				return
			}
			lastOut, lastErr = out2, err2
		} else {
			lastOut, lastErr = out1, err1
		}
		time.Sleep(400 * time.Millisecond)
	}

	t.Fatalf("Postgres not query-ready within %s.\nLast error: %v\nLast output:\n%s", timeout, lastErr, string(lastOut))
}
