[![build](https://github.com/linkdata/certstream/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/certstream/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/certstream/blob/coverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/certstream/blob/coverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/certstream?status.svg)](https://godoc.org/github.com/linkdata/certstream)

# CertStream

Small library wrapping github.com/google/certificate-transparency-go and github.com/FiloSottile/sunlight.

PostgreSQL is optional. Leave `Config.PgAddr` empty for live streaming without persistence.
Configure a database for certificate storage and backfill.

With database storage, an unparseable fetched CT entry gets a `CERTDB_entry`
row with `cert=0`. Gap scans do not refetch marked indexes, and unparseable
entries are not sent on `CertStream.C`. When certificate bytes are available,
`CERTDB_badcert` stores those bytes, their SHA-256 hash, and names recoverable
from the signed certificate body. Missing names use empty values. For
precertificates without full DER, `rawcert` holds TBS DER and `sha256` hashes
those stored bytes.

Streams with database and tail fetching enabled scan stored entry gaps at startup.
Within each pass, missing indexes are fetched in ascending order. Classic CT
logs request 256-index ranges aligned to 256, regardless of `LogBatchSize`.
Tiled logs fetch one aligned data tile of up to 256 entries at a time and use
it for every known hole in that tile. Only missing entries are stored. Each
fetch's missing entries commit as one database batch.
The durable `backfill_logindex` cursor advances through verified gap-free
ranges and after successful commits through the contiguous repaired prefix.
`GapScanIndex` tracks the cold scan position. It can be ahead of the durable
cursor and moves back when the scan retries a gap.
Cold scans start with a 10,000-index read, then read chunks of up to 100,000
indexes. Unfinished sweeps retry after 10 seconds; completed sweeps with
unresolved gaps retry after one minute. Scheduled scans pause when the database
queue exceeds 50%. A continuous request bypasses this gate and turns off after
a full sweep. Each gap read has a limit of five minutes; recent scans have a
budget of three seconds.
An unfinished sweep retries its oldest unresolved gap once, then continues
scanning later indexes if that gap remains unfilled.
The recent pass runs normally every 15 minutes after the cold cursor reaches
the recent range and no older sweep is unfinished. It covers up to one million
indexes below the database maximum; older indexes below the cursor are not audited.
When a fetched head range remains absent from the database across two scans,
up to 10,000 of those trailing indexes are fetched again.

When `Config.OnRetiredStreams` is set, each successfully fetched CT log list
passes database IDs of explicitly retired streams to the callback when any remain,
after their readers stop and queued database writes finish. Retired status is
recorded in the existing stream JSON; an explicitly listed non-retired status
clears it. Retired IDs remain eligible for later refreshes until their rows
are removed or the list explicitly reports another status.

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
