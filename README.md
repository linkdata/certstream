[![build](https://github.com/linkdata/certstream/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/certstream/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/certstream/blob/coverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/certstream/blob/coverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/certstream?status.svg)](https://godoc.org/github.com/linkdata/certstream)

# CertStream

Small library wrapping github.com/google/certificate-transparency-go and github.com/FiloSottile/sunlight.

PostgreSQL is optional. Leave `Config.PgAddr` empty for live streaming without persistence.
Configure a database for certificate storage and backfill.
Streams with database and tail fetching enabled scan stored entry gaps at startup
and every 15 minutes. Recent indexes are checked first in bounded windows;
older indexes are checked as database capacity permits. Scans pause when the
database queue exceeds 50%, and each gap query has a two-second deadline.
The recent pass covers up to one million indexes below the database maximum,
regardless of the persisted scan cursor. The older pass resumes that cursor;
indexes below an existing cursor and outside the recent range are not audited.
When a fetched head range remains absent from the database across two scans,
up to 10,000 of those trailing indexes are fetched again.

When `Config.OnRetiredStreams` is set, each successfully fetched CT log list
passes database IDs of explicitly retired streams to the callback when any remain,
after their readers stop and queued database writes finish. Retired status is
recorded in the existing stream JSON; an explicitly listed non-retired status
clears it. Retired IDs remain eligible for later refreshes until their rows
are removed or the list changes their status.

With `Config.Logger` set, gap discoveries are summarized per CT log every minute.
Summaries include the number of gaps and missing entries found during that interval,
including gaps larger than 1,000 entries, which are also logged immediately.
Pending counts are reported on shutdown. These are discoveries, not remaining backfill counts.

See [TUNING.md](TUNING.md) for PostgreSQL settings once the database grows past a few hundred GB.

```go
func grabdata() {
	fulllimiter := bwlimit.NewLimiter()
	fulldialer := fulllimiter.Wrap(nil)
	var filllimiter *bwlimit.Limiter
	var filldialer proxy.ContextDialer

	cfg := certstream.NewConfig()
	cfg.Logger = slog.Default()
	cfg.PgUser = "username"
	cfg.PgPass = "password"
	cfg.PgName = "certstream"
	cfg.PgAddr = "127.0.0.1:5432"
	cfg.HeadDialer = fulldialer
	filllimiter = bwlimit.NewLimiter(int64(1 * 1024 * 1024))
	filldialer = filllimiter.Wrap(fulldialer)
	cfg.TailDialer = filldialer

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	cs, err := certstream.Start(ctx, &wg, cfg)
	defer wg.Wait()

	if err != nil {
        panic(err)
	} else {
		for le := range cs.C {
			fmt.Printf("%q %v %v\n", le.Domain, le.Historical, le.Cert().DNSNames)
		}
	}
}
```
