// Package testpg provides isolated PostgreSQL databases for certstream tests.
package testpg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	image    = "postgres:18-alpine"
	baseDB   = "certstream"
	watchEnv = "CERTSTREAM_TESTPG_WATCHDOG"
)

const (
	// User is the PostgreSQL test user.
	User = "cert"
	// Password is the PostgreSQL test password.
	Password = "secretpass"
)

// Database identifies one test's isolated database in the shared server.
type Database struct {
	Addr string // Host and port of the shared server.
	Name string // Unique database name for this fixture.
}

// DSN returns the database connection string.
func (db Database) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", User, Password, db.Addr, db.Name)
}

var server struct {
	once     sync.Once
	addr     string
	watchdog *exec.Cmd
	pipe     io.WriteCloser
	err      error
}

// NewDatabase creates a test database and registers its removal with tb.
//
// All fixtures in the test process share one PostgreSQL container. Each call
// gets an independent database, so callers may use it in parallel. Connections
// opened with [Connect] close before database removal. Callers that open their
// own connections must register cleanup after NewDatabase.
// If Docker is unavailable, NewDatabase skips tb.
func NewDatabase(ctx context.Context, tb testing.TB) (db Database) {
	tb.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		tb.Skip("docker not found in PATH; skipping Postgres container portion")
	}
	server.once.Do(func() {
		server.addr, server.err = start(ctx)
	})
	if server.err != nil {
		tb.Fatalf("start PostgreSQL test container: %v", server.err)
	}

	name, err := randomName("certstream_test_")
	if err != nil {
		tb.Fatalf("name PostgreSQL test database: %v", err)
	}
	admin, err := pgx.Connect(ctx, adminDSN())
	if err != nil {
		tb.Fatalf("connect to PostgreSQL test server: %v", err)
	}
	_, createErr := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	closeErr := admin.Close(closeCtx)
	cancel()
	if createErr != nil {
		tb.Fatalf("create PostgreSQL test database: %v", createErr)
	}
	if closeErr != nil {
		tb.Fatalf("close PostgreSQL admin connection: %v", closeErr)
	}
	db = Database{Addr: server.addr, Name: name}
	tb.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer stop()
		admin, err := pgx.Connect(cleanupCtx, adminDSN())
		if err != nil {
			tb.Errorf("connect to drop PostgreSQL test database %s: %v", name, err)
			return
		}
		_, dropErr := admin.Exec(cleanupCtx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize())
		closeErr := admin.Close(cleanupCtx)
		if dropErr != nil {
			tb.Errorf("drop PostgreSQL test database %s: %v", name, dropErr)
		}
		if closeErr != nil {
			tb.Errorf("close PostgreSQL admin connection: %v", closeErr)
		}
	})
	return
}

// Connect opens a fixture connection and registers its closure with tb.
//
// Call it after [NewDatabase] so its cleanup runs before database removal.
func Connect(ctx context.Context, tb testing.TB, db Database) (conn *pgx.Conn) {
	tb.Helper()
	var err error
	if conn, err = pgx.Connect(ctx, db.DSN()); err != nil {
		tb.Fatalf("pgx connect failed: %v", err)
	}
	tb.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := conn.Close(closeCtx); err != nil {
			tb.Errorf("pgx close failed: %v", err)
		}
	})
	return
}

// Close waits for removal of the shared PostgreSQL container.
//
// It returns nil if no fixture started the server.
func Close() (err error) {
	if server.watchdog != nil {
		err = errors.Join(server.pipe.Close(), server.watchdog.Wait())
	}
	return
}

// RunWatchdog removes the shared container when its parent test process exits.
//
// It returns handled when this process is the cleanup child of a test process.
// When handled is true, the caller must exit after checking err.
func RunWatchdog() (handled bool, err error) {
	name, handled := os.LookupEnv(watchEnv)
	if handled {
		signal.Ignore(os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
		_, readErr := io.Copy(io.Discard, os.Stdin)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, removeErr := run(ctx, "docker", "rm", "-f", "-v", name)
		if removeErr != nil {
			removeErr = fmt.Errorf("remove PostgreSQL test container %s: %w\n%s", name, removeErr, out)
		}
		err = errors.Join(readErr, removeErr)
	}
	return
}

func adminDSN() string {
	return Database{Addr: server.addr, Name: baseDB}.DSN()
}

func randomName(prefix string) (name string, err error) {
	var suffix [6]byte
	if _, err = rand.Read(suffix[:]); err == nil {
		name = prefix + hex.EncodeToString(suffix[:])
	}
	return
}

func start(ctx context.Context) (addr string, err error) {
	if out, runErr := run(ctx, "docker", "pull", image); runErr != nil {
		err = fmt.Errorf("docker pull %s: %w\n%s", image, runErr, out)
		return
	}
	var name string
	if name, err = randomName("certstream-tests-"); err != nil {
		return
	}
	if err = startWatchdog(name); err != nil {
		return
	}
	// Parallel fixtures share this server and can open several pools at once.
	if out, runErr := run(ctx, "docker", "run", "-d",
		"--name", name,
		"-e", "POSTGRES_USER="+User,
		"-e", "POSTGRES_PASSWORD="+Password,
		"-e", "POSTGRES_DB="+baseDB,
		"-P", image, "-c", "max_connections=500"); runErr != nil {
		err = fmt.Errorf("docker run: %w\n%s", runErr, out)
		return
	}
	var out []byte
	if out, err = run(ctx, "docker", "port", name, "5432/tcp"); err != nil {
		err = fmt.Errorf("docker port: %w\n%s", err, out)
		return
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if pos := strings.LastIndexByte(line, ':'); pos >= 0 && pos+1 < len(line) {
			addr = "127.0.0.1:" + strings.TrimSpace(line[pos+1:])
			break
		}
	}
	if addr == "" {
		err = fmt.Errorf("docker port returned no mapped PostgreSQL port: %q", out)
		return
	}
	readyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		var conn *pgx.Conn
		conn, err = pgx.Connect(readyCtx, Database{Addr: addr, Name: baseDB}.DSN())
		if err == nil {
			closeCtx, stop := context.WithTimeout(context.WithoutCancel(readyCtx), 5*time.Second)
			err = conn.Close(closeCtx)
			stop()
			return
		}
		select {
		case <-readyCtx.Done():
			err = fmt.Errorf("PostgreSQL test server not ready: %w (last connection error: %v)", readyCtx.Err(), err)
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func startWatchdog(name string) (err error) {
	if _, alreadyWatching := os.LookupEnv(watchEnv); alreadyWatching {
		return errors.New("PostgreSQL watchdog cannot start another watchdog")
	}
	var executable string
	if executable, err = os.Executable(); err != nil {
		return
	}
	cmd := exec.Command(executable)
	cmd.Env = append(os.Environ(), watchEnv+"="+name)
	cmd.Stderr = os.Stderr
	var pipe io.WriteCloser
	if pipe, err = cmd.StdinPipe(); err == nil {
		if err = cmd.Start(); err == nil {
			server.watchdog = cmd
			server.pipe = pipe
		} else {
			err = errors.Join(err, pipe.Close())
		}
	}
	return
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
