[![build](https://github.com/linkdata/certstream/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/certstream/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/certstream/blob/coverage/main/badge.svg)](https://htmlpreview.github.io/?https://github.com/linkdata/certstream/blob/coverage/main/report.html)
[![goreport](https://goreportcard.com/badge/github.com/linkdata/certstream)](https://goreportcard.com/report/github.com/linkdata/certstream)
[![Docs](https://godoc.org/github.com/linkdata/certstream?status.svg)](https://godoc.org/github.com/linkdata/certstream)

# CertStream

Small library wrapping github.com/google/certificate-transparency-go and github.com/FiloSottile/sunlight.

Requires a Postgres database to use.

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
