package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/linkdata/bwlimit"
	"github.com/linkdata/certstream"
	"golang.org/x/net/proxy"
)

func env(key, dflt string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		val = dflt
	}
	return os.ExpandEnv(val)
}

var (
	flagPgUser     = flag.String("pguser", env("PGUSER", "certstream"), "database user")
	flagPgPass     = flag.String("pgpass", env("PGPASS", "certstream"), "database password")
	flagPgName     = flag.String("pgname", env("PGNAME", "certstream"), "database name")
	flagPgAddr     = flag.String("pgaddr", env("PGADDR", ""), "database address")
	flagPgPrefix   = flag.String("pgprefix", env("PGPREFIX", "certdb_"), "database naming prefix")
	flagPgConns    = flag.Int("pgconns", 100, "max number of database connections")
	flagPgBackfill = flag.Float64("pgbackfill", 1, "backfill rate limit in MB/sec, zero for no backfill")
	flagMaxEntries = flag.Int("maxentries", 100, "stop after printing this many entries (zero for no limit)")
)

func main() {
	flag.Parse()

	fulllimiter := bwlimit.NewLimiter()
	fulldialer := fulllimiter.Wrap(nil)
	var filllimiter *bwlimit.Limiter
	var filldialer proxy.ContextDialer

	cfg := certstream.NewConfig()
	cfg.Logger = slog.Default()
	cfg.HeadDialer = fulldialer
	cfg.PgAddr = *flagPgAddr
	cfg.PgUser = *flagPgUser
	cfg.PgName = *flagPgName
	cfg.PgConns = *flagPgConns
	cfg.PgPass = *flagPgPass
	cfg.PgPrefix = *flagPgPrefix
	if *flagPgBackfill > 0 {
		filllimiter = bwlimit.NewLimiter(int64(*flagPgBackfill * 1024 * 1024))
		filldialer = filllimiter.Wrap(fulldialer)
		cfg.TailDialer = filldialer
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	cs, err := certstream.Start(ctx, &wg, cfg)
	defer wg.Wait()

	if err != nil {
		fmt.Println(err)
	} else {
		n := 0
		for le := range cs.C {
			n++
			fmt.Printf("%5d %q %v %v\n", n, le.Domain, le.Historical, le.Cert().DNSNames)
			if n >= *flagMaxEntries {
				stop()
				break
			}
		}
	}
}
