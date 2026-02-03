package certstream_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/linkdata/bwlimit"
	"github.com/linkdata/certstream"
	"golang.org/x/net/proxy"
)

const (
	pgImage = "postgres:18-alpine"
	pgUser  = "cert"
	pgPass  = "secretpass"
	pgDB    = "certstream"
	pgPort  = "5432"
)

func testIntegrationMain(t *testing.T, hostPort string) {
	const maxEntries = 100

	fulllimiter := bwlimit.NewLimiter()
	fulldialer := fulllimiter.Wrap(nil)
	var filllimiter *bwlimit.Limiter
	var filldialer proxy.ContextDialer

	cfg := certstream.NewConfig()
	cfg.Logger = slog.Default()
	cfg.PgUser = pgUser
	cfg.PgPass = pgPass
	cfg.PgName = pgDB
	cfg.PgAddr = "127.0.0.1:" + hostPort
	cfg.PgNoSSL = true
	cfg.HeadDialer = fulldialer
	filllimiter = bwlimit.NewLimiter(int64(1 * 1024 * 1024))
	filldialer = filllimiter.Wrap(fulldialer)
	cfg.TailDialer = filldialer

	ctx, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	cs, err := certstream.Start(ctx, &wg, cfg)
	defer func() {
		wg.Wait()
		cs.Close()
	}()

	if err != nil {
		t.Fatal(err)
	} else {
		n := 0
		for le := range cs.C {
			n++
			t.Logf("%5d %q %v %v\n", n, le.Domain, le.Historical, le.Cert().DNSNames)
			if n >= maxEntries {
				stop()
				break
			}
		}
		for k, v := range certstream.GetHTTPCallsMap() {
			t.Logf("%q: %v\n", k, v)
		}
	}
}

// Test_EndToEnd_DefaultStreams_PostgresContainer
// - starts Postgres in Docker
// - discovers host port
// - builds a DSN
// - inspects `certstream --help` to discover the *current* flags
// - runs `certstream` against Postgres in a bounded mode (if supported)
// No CT log URL is passed; the binary uses its defaults to access all published streams.
func Test_EndToEnd_DefaultStreams_PostgresContainer(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()

	// Require docker
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH; skipping Postgres container portion")
	}

	// Pull & run Postgres
	cname := "certstream-it-" + randHex(6)
	if out, err := run(ctx, "docker", "pull", pgImage); err != nil {
		t.Fatalf("docker pull %s failed: %v\n%s", pgImage, err, out)
	}

	if out, err := run(ctx, "docker", "run", "--rm", "-d",
		"--name", cname,
		"-e", "POSTGRES_USER="+pgUser,
		"-e", "POSTGRES_PASSWORD="+pgPass,
		"-e", "POSTGRES_DB="+pgDB,
		"-P", pgImage); err != nil {
		t.Fatalf("docker run failed: %v\n%s", err, out)
	}
	defer func() {
		_, _ = run(context.Background(), "docker", "kill", cname)
	}()

	hostPort := dockerMappedPort(ctx, t, cname, "5432/tcp")

	waitForPostgresQueryReady(ctx, t, cname, pgUser, pgPass, pgDB, 2*time.Minute)

	testIntegrationMain(t, hostPort)
}

// ---------------- helpers ----------------

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
			// Expect lines like: "0.0.0.0:49162" or "[::]:49162"
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

func waitForPostgresQueryReady(ctx context.Context, t *testing.T, cname, user, pass, db string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastOut []byte
	var lastErr error

	for time.Now().Before(deadline) {
		// Step 1: readiness (accepting connections)
		out1, err1 := run(ctx, "docker", "exec", cname,
			"pg_isready", "-h", "127.0.0.1", "-p", pgPort, "-U", user, "-d", db,
		)
		if err1 == nil && bytes.Contains(out1, []byte("accepting connections")) {
			// Step 2: can execute a simple query
			out2, err2 := run(ctx, "docker", "exec",
				"-e", "PGPASSWORD="+pass, cname,
				"psql", "-h", "127.0.0.1", "-p", pgPort, "-U", user, "-d", db,
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
