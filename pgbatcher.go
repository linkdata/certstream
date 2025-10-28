package certstream

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/idna"
)

const batcherQueueSize = 16 * 1024

/*func (cdb *PgDB) insertEntry(ctx context.Context, le *LogEntry) (err error) {
	var conn *pgxpool.Conn
	if conn, err = cdb.Acquire(ctx); err == nil {
		defer conn.Release()
		args := cdb.insertCertArgs(le)
		start := time.Now()
		var certid int64
		if err = conn.QueryRow(ctx, cdb.stmtEnsureCert, args[:14]...).Scan(&certid); err == nil {
			args[14] = certid
			_, err = conn.Exec(ctx, cdb.stmtAttachMetadata, args[14:]...)
		}
		elapsed := time.Since(start)
		cdb.mu.Lock()
		cdb.newentrycount++
		cdb.newentrytime += elapsed
		cdb.mu.Unlock()
	}
	return
}*/

func (cdb *PgDB) insertCert(ctx context.Context, le *LogEntry) (args []any, err error) {
	args = cdb.insertCertArgs(le)
	start := time.Now()
	err = cdb.QueryRow(ctx, cdb.stmtEnsureCert, args[:14]...).Scan(&args[14])
	elapsed := time.Since(start)
	args = args[14:]
	cdb.mu.Lock()
	cdb.newentrycount++
	cdb.newentrytime += elapsed
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) runBatch(ctx context.Context, batch *pgx.Batch) (err error) {
	now := time.Now()
	err = cdb.SendBatch(ctx, batch).Close()
	elapsed := time.Since(now)
	cdb.mu.Lock()
	cdb.newentrycount += int64(len(batch.QueuedQueries))
	cdb.newentrytime += elapsed
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, idlecount int) {
	cdb.Workers.Add(1)
	defer func() {
		cdb.Workers.Add(-1)
		wg.Done()
	}()

	batch := &pgx.Batch{}
	for idlecount != 0 {
		select {
		case <-ctx.Done():
			idlecount = 0
		case le, ok := <-cdb.batchCh:
			if ok {
				if args, err := cdb.insertCert(ctx, le); err == nil {
					batch.Queue(cdb.stmtAttachMetadata, args...)
					select {
					case <-ctx.Done():
						idlecount = 0
					case le.getSendEntryCh() <- le:
					}
				} else {
					_ = cdb.LogError(err, "insertCert")
					ok = false
				}
			}
			if !ok {
				idlecount = 0
			}
		default:
			if idlecount > 0 {
				idlecount--
				time.Sleep(time.Millisecond * 100)
			}
		}
		if l := len(batch.QueuedQueries); l > 0 && (l >= BatchSize || idlecount == 0) {
			if cdb.LogError(cdb.runBatch(ctx, batch), "runBatch") != nil {
				idlecount = 0
			}
			batch = &pgx.Batch{}
		}
	}
	/*
		for {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case le, ok := <-cdb.getBatchCh():
				if !ok {
					return
				}
				if cdb.LogError(cdb.insertEntry(ctx, le), "worker") != nil {
					return
				}
				select {
				case <-ctx.Done():
				case le.getSendEntryCh() <- le:
				}
			default:
				if idlecount > 0 {
					idlecount--
					if idlecount == 0 {
						return
					}
				}
				time.Sleep(time.Millisecond * 100)
			}
		}
	*/
}

func (cdb *PgDB) AverageNewEntryTime() (d time.Duration) {
	cdb.mu.Lock()
	d = cdb.avgentrytime
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) runWorkers(ctx context.Context, wg *sync.WaitGroup) {
	const interval = time.Millisecond * 100
	defer wg.Done()

	wg.Add(1)
	go cdb.worker(ctx, wg, -1)

	loaded := 0
	ticks := 0
	ticker := time.NewTicker(interval)
	avgentrytimes := make([]time.Duration, time.Second*10/interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cdb.mu.Lock()
			avgentrytime := cdb.newentrytime
			if d := time.Duration(cdb.newentrycount); d > 0 {
				avgentrytime /= d
			}
			cdb.newentrytime = 0
			cdb.newentrycount = 0
			avgentrytimes[ticks] = avgentrytime
			ticks++
			if ticks >= cap(avgentrytimes) {
				ticks = 0
			}
			avgentrytime = 0
			for _, d := range avgentrytimes {
				avgentrytime += d
			}
			cdb.avgentrytime = avgentrytime / time.Duration(cap(avgentrytimes))
			cdb.mu.Unlock()

			if cdb.QueueUsage() > 30 {
				loaded++
				if loaded > 10 {
					loaded /= 2
					wg.Add(1)
					go cdb.worker(ctx, wg, 10)
				}
			} else {
				loaded = 0
			}
		}
	}
}
func (cdb *PgDB) insertCertArgs(le *LogEntry) (args []any) {
	if le != nil {
		if cert := le.Cert(); cert != nil {
			logindex := le.Index()

			var dnsnames []string
			for _, dnsname := range cert.DNSNames {
				dnsname = strings.ToLower(dnsname)
				if uniname, err := idna.ToUnicode(dnsname); err == nil && uniname != dnsname {
					dnsnames = append(dnsnames, uniname)
				} else {
					dnsnames = append(dnsnames, dnsname)
				}
			}

			var ipaddrs []string
			for _, ip := range cert.IPAddresses {
				ipaddrs = append(ipaddrs, ip.String())
			}

			var emails []string
			for _, email := range cert.EmailAddresses {
				emails = append(emails, strings.ReplaceAll(email, " ", "_"))
			}

			var uris []string
			for _, uri := range cert.URIs {
				uris = append(uris, strings.ReplaceAll(uri.String(), " ", "%20"))
			}

			args = []any{
				strings.Join(cert.Issuer.Organization, ","),
				strings.Join(cert.Issuer.Province, ","),
				strings.Join(cert.Issuer.Country, ","),
				strings.Join(cert.Subject.Organization, ","),
				strings.Join(cert.Subject.Province, ","),
				strings.Join(cert.Subject.Country, ","),
				cert.NotBefore,
				cert.NotAfter,
				cert.GetCommonName(),
				cert.Signature,
				cert.PreCert,
				cert.Seen,
				le.LogStream.Id,
				logindex,
				int64(-123), // cert ID placeholder
				strings.Join(dnsnames, " "),
				strings.Join(ipaddrs, " "),
				strings.Join(emails, " "),
				strings.Join(uris, " "),
			}
		}
	}
	return
}
