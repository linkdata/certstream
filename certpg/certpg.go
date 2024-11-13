package certpg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/linkdata/certstream"
	"golang.org/x/net/idna"
)

// CertPG integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type CertPG struct {
	*sql.DB
	certstream.Logger
	funcOperatorID   *sql.Stmt
	funcStreamID     *sql.Stmt
	procNewEntry     *sql.Stmt
	stmtSelectGaps   *sql.Stmt
	stmtSelectMinIdx *sql.Stmt
	stmtSelectMaxIdx *sql.Stmt
}

// New creates a CertPG and creates the needed tables and indices if they don't exist.
func New(ctx context.Context, db *sql.DB, prefix string) (cdb *CertPG, err error) {
	const callCreateSchema = `CALL CERTDB_create_schema();`
	const callOperatorID = `SELECT CERTDB_operator_id($1,$2);`
	const callStreamID = `SELECT CERTDB_stream_id($1,$2,$3);`
	const callNewEntry = `CALL CERTDB_new_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17);`
	pfx := func(s string) string { return strings.ReplaceAll(s, "CERTDB_", prefix) }

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
												cdb = &CertPG{
													DB:               db,
													funcOperatorID:   getOperatorID,
													funcStreamID:     getStreamID,
													procNewEntry:     procNewEntry,
													stmtSelectGaps:   stmtSelectGaps,
													stmtSelectMinIdx: stmtSelectMinIdx,
													stmtSelectMaxIdx: stmtSelectMaxIdx,
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

func dbRes(res sql.Result) string {
	rowId, _ := res.LastInsertId()
	numRows, _ := res.RowsAffected()
	return fmt.Sprintf("rowId=%v numRows=%v", rowId, numRows)
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
		var seen time.Time
		var sig []byte

		if atomic.CompareAndSwapInt32(&le.Backfilled, 0, 1) {
			go cdb.Backfill(ctx, le.LogStream)
		}

		logindex := le.Index()

		if le.RawLogEntry != nil {
			seen = time.UnixMilli(int64(le.RawLogEntry.Leaf.TimestampedEntry.Timestamp)).UTC()
			shasig := sha256.Sum256(le.RawLogEntry.Cert.Data)
			sig = shasig[:]
		} else {
			seen = time.Now().UTC()
			shasig := sha256.Sum256(cert.RawTBSCertificate)
			sig = shasig[:]
		}

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
			seen,
			le.LogStream.Id,
			logindex,
			sig,
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
				fmt.Printf("CALL CERTDB_new_entry('%v', %v,%v,'%x', '%s','%s','%s', '%s','%s','%s', '%s','%s', '%s', '%s','%s','%s','%s')\n", args...)
			}
		}
	}
	return
}
