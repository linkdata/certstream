package certstream

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/linkdata/bwlimit"
	"golang.org/x/net/idna"
)

type Scanner interface {
	Scan(dest ...any) error
}

func env(key, dflt string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		val = dflt
	}
	return os.ExpandEnv(val)
}

var (
	flagPgUser         = flag.String("pguser", env("PGUSER", "certstream"), "database user")
	flagPgPass         = flag.String("pgpass", env("PGPASS", "certstream"), "database password")
	flagPgName         = flag.String("pgname", env("PGNAME", "certstream"), "database name")
	flagPgAddr         = flag.String("pgaddr", env("PGADDR", ""), "database address")
	flagPgPrefix       = flag.String("pgprefix", env("PGPREFIX", "certdb_"), "database naming prefix")
	flagPgConns        = flag.Int("pgconns", 100, "max number of database connections")
	flagPgBackfill     = flag.Bool("pgbackfill", false, "backfill missing database log entries")
	flagPgBackfillRate = flag.Int("pgbackfillrate", 10*1000000, "backfill rate limit in bytes/sec")
)

// PgDB integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type PgDB struct {
	*CertStream
	*pgxpool.Pool
	bwlimit.ContextDialer                     // if not nil, ContextDialer used for backfilling
	Pfx                   func(string) string // prefix replacer
	funcOperatorID        string
	funcStreamID          string
	procNewEntry          string
	stmtSelectGaps        string
	stmtSelectMinIdx      string
	stmtSelectMaxIdx      string
	stmtSelectDnsnameLike string
}

func ensureSchema(ctx context.Context, db *pgxpool.Pool, pfx func(string) string) (err error) {
	const callCreateSchema = `CALL CERTDB_create_schema();`
	if _, err = db.Exec(ctx, pfx(FunctionName)); err == nil {
		if _, err = db.Exec(ctx, pfx(ProcedureCreateSchema)); err == nil {
			if _, err = db.Exec(ctx, pfx(callCreateSchema)); err == nil {
				if _, err = db.Exec(ctx, pfx(FunctionOperatorID)); err == nil {
					if _, err = db.Exec(ctx, pfx(FunctionStreamID)); err == nil {
						_, err = db.Exec(ctx, pfx(ProcedureNewEntry))
					}
				}
			}
		}
	}
	return
}

// NewPgDB creates a PgDB and creates the needed tables and indices if they don't exist.
func NewPgDB(ctx context.Context, cs *CertStream) (cdb *PgDB, err error) {
	const callOperatorID = `SELECT CERTDB_operator_id($1,$2);`
	const callStreamID = `SELECT CERTDB_stream_id($1,$2,$3);`
	const callNewEntry = `CALL CERTDB_new_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18);`
	if *flagPgAddr != "" {
		dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?pool_max_conns=%d&pool_max_conn_idle_time=1m",
			*flagPgUser, *flagPgPass, *flagPgAddr, *flagPgName, *flagPgConns)
		var poolcfg *pgxpool.Config
		if poolcfg, err = pgxpool.ParseConfig(dsn); err == nil {
			var pool *pgxpool.Pool
			if pool, err = pgxpool.NewWithConfig(ctx, poolcfg); err == nil {
				if err = pool.Ping(ctx); err == nil {
					cs.LogInfo("database connected", "addr", *flagPgAddr)
					pfx := func(s string) string { return strings.ReplaceAll(s, "CERTDB_", *flagPgPrefix) }
					if err = ensureSchema(ctx, pool, pfx); err == nil {
						cdb = &PgDB{
							CertStream:            cs,
							Pool:                  pool,
							Pfx:                   pfx,
							funcOperatorID:        pfx(callOperatorID),
							funcStreamID:          pfx(callStreamID),
							procNewEntry:          pfx(callNewEntry),
							stmtSelectGaps:        pfx(SelectGaps),
							stmtSelectMinIdx:      pfx(SelectMinIndex),
							stmtSelectMaxIdx:      pfx(SelectMaxIndex),
							stmtSelectDnsnameLike: pfx(SelectDnsnameLike),
						}
					}
				}
			}
		}
	}
	return
}

func (cdb *PgDB) Operator(ctx context.Context, lo *LogOperator) (err error) {
	row := cdb.QueryRow(ctx, cdb.funcOperatorID, lo.Name, strings.Join(lo.Email, ","))
	err = row.Scan(&lo.Id)
	return
}

func (cdb *PgDB) Stream(ctx context.Context, ls *LogStream) (err error) {
	var b []byte
	if b, err = json.Marshal(ls.Log); err == nil {
		row := cdb.QueryRow(ctx, cdb.funcStreamID, ls.URL, ls.LogOperator.Id, string(b))
		err = row.Scan(&ls.Id)
	}
	return
}

func (cdb *PgDB) Entry(ctx context.Context, le *LogEntry) (err error) {
	if cert := le.Cert(); cert != nil {
		if *flagPgBackfill {
			if atomic.CompareAndSwapInt32(&le.Backfilled, 0, 1) {
				go cdb.BackfillStream(ctx, le.LogStream)
			}
		}

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

		args := []any{
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

		if _, err = cdb.Pool.Exec(ctx, cdb.procNewEntry, args...); err != nil {
			if ctx.Err() == nil {
				fmt.Printf("CALL CERTDB_new_entry('%v', %v,%v,%v,'%x', '%s','%s','%s', '%s','%s','%s', '%s','%s', '%s', '%s','%s','%s','%s')\n", args...)
			}
		}
	}
	return
}

func (cdb *PgDB) Estimate(table string) (estimate float64, err error) {
	if !strings.HasPrefix(table, "CERTDB_") {
		table = "CERTDB_" + table
	}
	row := cdb.Pool.QueryRow(context.Background(), SelectEstimate, cdb.Pfx(table))
	err = row.Scan(&estimate)
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
	rows, err := cdb.Query(ctx, cdb.Pfx(fmt.Sprintf("SELECT %s FROM CERTDB_%s WHERE cert=$1", colname, tablename)), id)
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
	cert.DNSNames = cdb.getCertStrings(ctx, dbcert.Id, "dnsname", "dnsname")
	cert.EmailAddresses = cdb.getCertStrings(ctx, dbcert.Id, "email", "email")
	cert.IPAddresses = cdb.getCertStrings(ctx, dbcert.Id, "ipaddress", "addr")
	cert.URIs = cdb.getCertStrings(ctx, dbcert.Id, "uri", "uri")
	return
}

func (cdb *PgDB) GetCertificateByLogEntry(ctx context.Context, entry *PgLogEntry) (cert *JsonCertificate, err error) {
	if cert, err = cdb.GetCertificateByID(ctx, entry.CertID); cert != nil {
		cert.Seen = entry.Seen
	}
	return
}

func (cdb *PgDB) GetCertificateByHash(ctx context.Context, hash []byte) (cert *JsonCertificate, err error) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE sha256=$1`), hash)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}

func (cdb *PgDB) GetCertificateByID(ctx context.Context, id int64) (cert *JsonCertificate, err error) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE id=$1`), id)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}
