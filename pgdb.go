package certstream

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/idna"
)

type Scanner interface {
	Scan(dest ...any) error
}

// PgDB integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type PgDB struct {
	*CertStream
	*pgxpool.Pool
	Pfx                   func(string) string // prefix replacer
	Workers               atomic.Int32
	funcOperatorID        string
	funcStreamID          string
	funcEnsureIdent       string
	stmtNewEntry          string
	stmtSelectGaps        string
	stmtSelectMinIdx      string
	stmtSelectMaxIdx      string
	stmtSelectDnsnameLike string
	mu                    sync.Mutex // protects following
	batchCh               chan *LogEntry
	estimates             map[string]float64 // row count estimates
	newentrytime          time.Duration
	newentrycount         int64
	avgentrytime          time.Duration
}

func ensureSchema(ctx context.Context, db *pgxpool.Pool, pfx func(string) string) (err error) {
	if _, err = db.Exec(ctx, pfx(CreateSchema)); err == nil {
		if _, err = db.Exec(ctx, pfx(FunctionOperatorID)); err == nil {
			if _, err = db.Exec(ctx, pfx(FunctionStreamID)); err == nil {
				_, err = db.Exec(ctx, pfx(ProcAddNewEntry))
			}
		}
	}
	return
}

// NewPgDB creates a PgDB and creates the needed tables and indices if they don't exist.
func NewPgDB(ctx context.Context, cs *CertStream) (cdb *PgDB, err error) {
	const callOperatorID = `SELECT CERTDB_operator_id($1,$2);`
	const callStreamID = `SELECT CERTDB_stream_id($1,$2,$3);`
	const callNewEntry = `CALL CERTDB_add_new_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18);`
	if cs.Config.PgAddr != "" {
		dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?pool_max_conns=%d&pool_max_conn_idle_time=1m",
			cs.Config.PgUser, cs.Config.PgPass, cs.Config.PgAddr, cs.Config.PgName, cs.Config.PgConns)
		var poolcfg *pgxpool.Config
		if poolcfg, err = pgxpool.ParseConfig(dsn); err == nil {
			var pool *pgxpool.Pool
			if pool, err = pgxpool.NewWithConfig(ctx, poolcfg); err == nil {
				if err = pool.Ping(ctx); err == nil {
					cs.LogInfo("database", "addr", cs.Config.PgAddr, "name", cs.Config.PgName, "prefix", cs.Config.PgPrefix)
					pfx := func(s string) string { return strings.ReplaceAll(s, "CERTDB_", cs.Config.PgPrefix) }
					if err = ensureSchema(ctx, pool, pfx); err == nil {
						var pgversion string
						if cs.LogError(pool.QueryRow(ctx, `SELECT version();`).Scan(&pgversion), "postgres version") == nil {
							cs.LogInfo("postgres", "version", pgversion)
						}
						cdb = &PgDB{
							CertStream:            cs,
							Pool:                  pool,
							Pfx:                   pfx,
							funcOperatorID:        pfx(callOperatorID),
							funcStreamID:          pfx(callStreamID),
							funcEnsureIdent:       pfx(`SELECT CERTDB_ensure_ident($1,$2,$3);`),
							stmtNewEntry:          pfx(callNewEntry),
							stmtSelectGaps:        pfx(SelectGaps),
							stmtSelectMinIdx:      pfx(SelectMinIndex),
							stmtSelectMaxIdx:      pfx(SelectMaxIndex),
							stmtSelectDnsnameLike: pfx(SelectDnsnameLike),
							batchCh:               make(chan *LogEntry, batcherQueueSize),
							estimates: map[string]float64{
								"cert":   0,
								"domain": 0,
								"entry":  0,
							},
						}
						cdb.refreshEstimates(ctx)
					}
				}
			}
		}
	}
	return
}

func (cdb *PgDB) Close() {
	close(cdb.batchCh)
	cdb.Pool.Close()
}

func (cdb *PgDB) QueueUsage() (pct int) {
	pct = len(cdb.batchCh) * 100 / batcherQueueSize
	return
}

func (cdb *PgDB) sendToBatcher(ctx context.Context, le *LogEntry) {
	select {
	case <-ctx.Done():
	case cdb.batchCh <- le:
	}
}

func (cdb *PgDB) ensureOperator(ctx context.Context, lo *LogOperator) (err error) {
	if cdb != nil {
		row := cdb.QueryRow(ctx, cdb.funcOperatorID, lo.Name, strings.Join(lo.Email, ","))
		err = wrapErr(row.Scan(&lo.Id), cdb.funcOperatorID)
	}
	return
}

func (cdb *PgDB) ensureStream(ctx context.Context, ls *LogStream) (err error) {
	if cdb != nil {
		var b []byte
		if b, err = json.Marshal(ls.Log); err == nil {
			row := cdb.QueryRow(ctx, cdb.funcStreamID, ls.URL, ls.LogOperator.Id, string(b))
			err = wrapErr(row.Scan(&ls.Id), cdb.funcStreamID)
		}
	}
	return
}

func (cdb *PgDB) queueEntry(le *LogEntry) (args []any) {
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
			cert.Seen,
			le.LogStream.Id,
			logindex,
			cert.PreCert,
			cert.Signature,
			strings.Join(cert.Issuer.Organization, ","),
			strings.Join(cert.Issuer.Province, ","),
			strings.Join(cert.Issuer.Country, ","),
			strings.Join(cert.Subject.Organization, ","),
			strings.Join(cert.Subject.Province, ","),
			strings.Join(cert.Subject.Country, ","),
			cert.NotBefore,
			cert.NotAfter,
			cert.Subject.CommonName,
			strings.Join(dnsnames, " "),
			strings.Join(ipaddrs, " "),
			strings.Join(emails, " "),
			strings.Join(uris, " "),
		}
	}
	return
}

func (cdb *PgDB) fillIdentity(ctx context.Context, id int, ident *JsonIdentity) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_ident WHERE id=$1;`), id)
	var dbident PgIdent
	if err := cdb.LogError(ScanIdent(row, &dbident), "fillIdentity", "id", id); err == nil {
		ident.Country = dbident.Country
		ident.Organization = dbident.Organization
		ident.Province = dbident.Province
	}
}

func (cdb *PgDB) getCertStrings(ctx context.Context, id int64, tablename, colname string) (sl []string) {
	rows, err := cdb.Query(ctx, cdb.Pfx(fmt.Sprintf("SELECT %s::text FROM CERTDB_%s WHERE cert=$1;", colname, tablename)), id)
	if cdb.LogError(err, "getCertStrings/"+tablename, "id", id) == nil {
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := cdb.LogError(rows.Scan(&s), "getCertStrings/scan/"+tablename); err == nil {
				sl = append(sl, s)
			}
		}
	}
	return
}

func (cdb *PgDB) getCertificate(ctx context.Context, dbcert *PgCertificate) (cert *JsonCertificate, err error) {
	cert = &JsonCertificate{
		PreCert:        dbcert.PreCert,
		Signature:      dbcert.Sha256,
		DNSNames:       []string{},
		EmailAddresses: []string{},
		IPAddresses:    []string{},
		URIs:           []string{},
		NotBefore:      dbcert.NotBefore,
		NotAfter:       dbcert.NotAfter,
	}
	cdb.fillIdentity(ctx, dbcert.IssuerID, &cert.Issuer)
	cdb.fillIdentity(ctx, dbcert.SubjectID, &cert.Subject)
	cert.Subject.CommonName = dbcert.CommonName
	cert.DNSNames = cdb.getCertStrings(ctx, dbcert.Id, "dnsnames", "fqdn")
	cert.EmailAddresses = cdb.getCertStrings(ctx, dbcert.Id, "email", "email")
	cert.IPAddresses = cdb.getCertStrings(ctx, dbcert.Id, "ipaddress", "addr")
	for i := range cert.IPAddresses {
		cert.IPAddresses[i] = strings.TrimSuffix(cert.IPAddresses[i], "/32")
	}
	cert.URIs = cdb.getCertStrings(ctx, dbcert.Id, "uri", "uri")
	return
}

func (cdb *PgDB) GetCertificateByLogEntry(ctx context.Context, entry *PgLogEntry) (cert *JsonCertificate, err error) {
	return cdb.GetCertificateByID(ctx, entry.CertID)
}

func (cdb *PgDB) GetCertificatesByCommmonName(ctx context.Context, commonname string) (certs []*JsonCertificate, err error) {
	var rows pgx.Rows
	if rows, err = cdb.Query(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE commonname=$1 ORDER BY notbefore DESC;`), commonname); err == nil {
		defer rows.Close()
		for rows.Next() {
			var dbcert PgCertificate
			e := ScanCertificate(rows, &dbcert)
			if e == nil {
				var cert *JsonCertificate
				if cert, e = cdb.getCertificate(ctx, &dbcert); e == nil {
					certs = append(certs, cert)
				}
			}
			err = errors.Join(err, e)
		}
		err = errors.Join(err, rows.Err())
	}
	return
}

func (cdb *PgDB) GetCertificateByHash(ctx context.Context, hash []byte) (cert *JsonCertificate, err error) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE sha256=$1;`), hash)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}

func (cdb *PgDB) GetCertificateByID(ctx context.Context, id int64) (cert *JsonCertificate, err error) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE id=$1;`), id)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}

func (cdb *PgDB) Estimate(table string) (f float64) {
	table = strings.TrimPrefix(table, "CERTDB_")
	table = strings.TrimPrefix(table, cdb.CertStream.Config.PgPrefix)
	cdb.mu.Lock()
	f = cdb.estimates[table]
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) refreshEstimatesBatch() (batch *pgx.Batch) {
	batch = &pgx.Batch{}
	cdb.mu.Lock()
	defer cdb.mu.Unlock()
	for k := range cdb.estimates {
		table := cdb.Pfx("CERTDB_" + k)
		batch.Queue(SelectEstimate, table).QueryRow(func(row pgx.Row) error {
			var estimate float64
			if cdb.LogError(row.Scan(&estimate), "refreshEstimates", "table", table) == nil {
				cdb.mu.Lock()
				cdb.estimates[k] = estimate
				cdb.mu.Unlock()
			}
			return nil
		})
	}
	return
}

func (cdb *PgDB) refreshEstimates(ctx context.Context) {
	if batch := cdb.refreshEstimatesBatch(); batch != nil {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		cdb.LogError(cdb.SendBatch(ctx, batch).Close(), "refreshEstimates")
	}
}

func (cdb *PgDB) estimator(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cdb.refreshEstimates(ctx)
		}
	}
}
