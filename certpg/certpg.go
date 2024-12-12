package certpg

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

	"github.com/linkdata/bwlimit"
	"github.com/linkdata/certstream"
	"github.com/linkdata/certstream/certjson"
	"golang.org/x/net/idna"
)

type Scanner interface {
	Scan(dest ...any) error
}

// CertPG integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type CertPG struct {
	*sql.DB
	certstream.Logger
	Backfill              bool                // if true, fill in missing entries in database
	bwlimit.ContextDialer                     // if not nil, ContextDialer used for backfilling
	Pfx                   func(string) string // prefix replacer
	funcOperatorID        *sql.Stmt
	funcStreamID          *sql.Stmt
	procNewEntry          *sql.Stmt
	stmtSelectGaps        *sql.Stmt
	stmtSelectMinIdx      *sql.Stmt
	stmtSelectMaxIdx      *sql.Stmt
	stmtSelectDnsnameLike *sql.Stmt
}

// New creates a CertPG and creates the needed tables and indices if they don't exist.
func New(ctx context.Context, cd bwlimit.ContextDialer, db *sql.DB, prefix string) (cdb *CertPG, err error) {
	const callCreateSchema = `CALL CERTDB_create_schema();`
	const callOperatorID = `SELECT CERTDB_operator_id($1,$2);`
	const callStreamID = `SELECT CERTDB_stream_id($1,$2,$3);`
	const callNewEntry = `CALL CERTDB_new_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18);`
	pfx := func(s string) string { return strings.ReplaceAll(s, "CERTDB_", prefix) }

	if _, err = db.ExecContext(ctx, pfx(FunctionName)); err == nil {
		if _, err = db.ExecContext(ctx, pfx(ProcedureCreateSchema)); err == nil {
			if _, err = db.ExecContext(ctx, pfx(callCreateSchema)); err == nil {
				if _, err = db.ExecContext(ctx, pfx(FunctionOperatorID)); err == nil {
					if _, err = db.ExecContext(ctx, pfx(FunctionStreamID)); err == nil {
						if _, err = db.ExecContext(ctx, pfx(ProcedureNewEntry)); err == nil {
							var getOperatorID *sql.Stmt
							if getOperatorID, err = db.PrepareContext(ctx, pfx(callOperatorID)); err == nil {
								var getStreamID *sql.Stmt
								if getStreamID, err = db.PrepareContext(ctx, pfx(callStreamID)); err == nil {
									var procNewEntry *sql.Stmt
									if procNewEntry, err = db.PrepareContext(ctx, pfx(callNewEntry)); err == nil {
										var stmtSelectGaps *sql.Stmt
										if stmtSelectGaps, err = db.PrepareContext(ctx, pfx(SelectGaps)); err == nil {
											var stmtSelectMinIdx *sql.Stmt
											if stmtSelectMinIdx, err = db.PrepareContext(ctx, pfx(SelectMinIndex)); err == nil {
												var stmtSelectMaxIdx *sql.Stmt
												if stmtSelectMaxIdx, err = db.PrepareContext(ctx, pfx(SelectMaxIndex)); err == nil {
													var stmtSelectDnsnameLike *sql.Stmt
													if stmtSelectDnsnameLike, err = db.PrepareContext(ctx, pfx(SelectDnsnameLike)); err == nil {
														cdb = &CertPG{
															DB:                    db,
															ContextDialer:         cd,
															Pfx:                   pfx,
															funcOperatorID:        getOperatorID,
															funcStreamID:          getStreamID,
															procNewEntry:          procNewEntry,
															stmtSelectGaps:        stmtSelectGaps,
															stmtSelectMinIdx:      stmtSelectMinIdx,
															stmtSelectMaxIdx:      stmtSelectMaxIdx,
															stmtSelectDnsnameLike: stmtSelectDnsnameLike,
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return
}

func (cdb *CertPG) LogError(err error, msg string, args ...any) error {
	if err != nil && cdb.Logger != nil {
		if !errors.Is(err, context.Canceled) {
			cdb.Logger.Error(msg, append(args, "err", err)...)
		}
	}
	return err
}

func closeAll(closers ...io.Closer) (err error) {
	for _, c := range closers {
		if c != nil {
			err = errors.Join(err, c.Close())
		}
	}
	return
}

// Close frees resources used.
func (cdb *CertPG) Close() error {
	return closeAll(
		cdb.funcOperatorID,
		cdb.funcStreamID,
		cdb.procNewEntry,
		cdb.stmtSelectGaps,
		cdb.stmtSelectMinIdx,
		cdb.stmtSelectMaxIdx,
	)
}

func (cdb *CertPG) Operator(ctx context.Context, lo *certstream.LogOperator) (err error) {
	row := cdb.funcOperatorID.QueryRowContext(ctx, lo.Name, strings.Join(lo.Email, ","))
	err = row.Scan(&lo.Id)
	return
}

func (cdb *CertPG) Stream(ctx context.Context, ls *certstream.LogStream) (err error) {
	var b []byte
	if b, err = json.Marshal(ls.Log); err == nil {
		row := cdb.funcStreamID.QueryRowContext(ctx, ls.URL, ls.LogOperator.Id, string(b))
		err = row.Scan(&ls.Id)
	}
	return
}

func (cdb *CertPG) Entry(ctx context.Context, le *certstream.LogEntry) (err error) {
	if cert := le.Cert(); cert != nil {
		if cdb.Backfill {
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

		if _, err = cdb.procNewEntry.ExecContext(ctx, args...); err != nil {
			if ctx.Err() == nil {
				fmt.Printf("CALL CERTDB_new_entry('%v', %v,%v,%v,'%x', '%s','%s','%s', '%s','%s','%s', '%s','%s', '%s', '%s','%s','%s','%s')\n", args...)
			}
		}
	}
	return
}

func (cdb *CertPG) Estimate(table string) (estimate float64, err error) {
	if !strings.HasPrefix(table, "CERTDB_") {
		table = "CERTDB_" + table
	}
	row := cdb.QueryRow(SelectEstimate, cdb.Pfx(table))
	err = row.Scan(&estimate)
	return
}

func (cdb *CertPG) fillIdentity(ctx context.Context, id int, ident *certjson.Identity) {
	row := cdb.QueryRowContext(ctx, cdb.Pfx(`SELECT * FROM CERTDB_ident WHERE id=$1`), id)
	var dbident Ident
	if err := cdb.LogError(ScanIdent(row, &dbident), "fillIdentity", "id", id); err == nil {
		ident.Country = dbident.Country
		ident.Organization = dbident.Organization
		ident.Province = dbident.Province
	}
}

func (cdb *CertPG) getCertStrings(ctx context.Context, id int64, tablename, colname string) (sl []string) {
	rows, err := cdb.QueryContext(ctx, cdb.Pfx(fmt.Sprintf("SELECT %s FROM CERTDB_%s WHERE cert=$1", colname, tablename)), id)
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

func (cdb *CertPG) getCertificate(ctx context.Context, dbcert *Certificate) (cert *certjson.Certificate, err error) {
	cert = &certjson.Certificate{
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

func (cdb *CertPG) GetCertificateByLogEntry(ctx context.Context, entry *LogEntry) (cert *certjson.Certificate, err error) {
	if cert, err = cdb.GetCertificateByID(ctx, entry.CertID); cert != nil {
		cert.Seen = entry.Seen
	}
	return
}

func (cdb *CertPG) GetCertificateByHash(ctx context.Context, hash []byte) (cert *certjson.Certificate, err error) {
	row := cdb.QueryRowContext(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE sha256=$1`), hash)
	var dbcert Certificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}

func (cdb *CertPG) GetCertificateByID(ctx context.Context, id int64) (cert *certjson.Certificate, err error) {
	row := cdb.QueryRowContext(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE id=$1`), id)
	var dbcert Certificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}
