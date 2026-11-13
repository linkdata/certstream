package certstream_test

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/linkdata/bwlimit"
	"github.com/linkdata/certstream"
	"github.com/linkdata/certstream/internal/testpg"
	"golang.org/x/net/proxy"
)

func testIntegrationMain(t *testing.T, fixture testpg.Database) {
	const maxEntries = 100

	fulllimiter := bwlimit.NewLimiter()
	fulldialer := fulllimiter.Wrap(nil)
	var filllimiter *bwlimit.Limiter
	var filldialer proxy.ContextDialer

	cfg := certstream.NewConfig()
	cfg.Logger = slog.Default()
	cfg.PgUser = testpg.User
	cfg.PgPass = testpg.Password
	cfg.PgName = fixture.Name
	cfg.PgAddr = fixture.Addr
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

// Test_EndToEnd_DefaultStreams_PostgresContainer uses the default published streams.
func Test_EndToEnd_DefaultStreams_PostgresContainer(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	fixture := testpg.NewDatabase(ctx, t)
	testIntegrationMain(t, fixture)
}
