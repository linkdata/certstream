package certpg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/linkdata/certstream"
	"golang.org/x/net/idna"
)

// CertPG integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type CertPG struct {
	*sql.DB
	certstream.Logger
	getOperatorID *sql.Stmt
	getStreamID   *sql.Stmt
	procNewEntry  *sql.Stmt
}

func prepare(perr *error, db *sql.DB, txt string) (stmt *sql.Stmt) {
	var err error
	if stmt, err = db.Prepare(setPrefix(txt)); err != nil {
		*perr = errors.Join(*perr, fmt.Errorf("%q: %v", txt, err))
	}
	return
}

// New creates a Certdb and creates the needed tables and indices if they don't exist.
func New(ctx context.Context, db *sql.DB) (cdb *CertPG, err error) {
	if err = CreateSchema(ctx, db); err == nil {
		cdb = &CertPG{
			DB:            db,
			getOperatorID: prepare(&err, db, `SELECT CERTDB_operator_id($1,$2);`),
			getStreamID:   prepare(&err, db, `SELECT CERTDB_stream_id($1,$2,$3);`),
			procNewEntry:  prepare(&err, db, `CALL CERTDB_new_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17);`),
		}
		if err != nil {
			cdb.Close()
			cdb = nil
		}
	}
	return
}

func closeAll(closers ...io.Closer) (err error) {
	for _, c := range closers {
		if c != nil {
			err = errors.Join(err, c.Close())
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

// Close frees resources used.
func (cdb *CertPG) Close() error {
	return closeAll(
		cdb.getOperatorID,
		cdb.getStreamID,
		cdb.procNewEntry,
	)
}

func dbRes(res sql.Result) string {
	rowId, _ := res.LastInsertId()
	numRows, _ := res.RowsAffected()
	return fmt.Sprintf("rowId=%v numRows=%v", rowId, numRows)
}

func (cdb *CertPG) Operator(ctx context.Context, lo *certstream.LogOperator) (err error) {
	row := cdb.getOperatorID.QueryRowContext(ctx, lo.Name, strings.Join(lo.Email, ","))
	err = row.Scan(&lo.Id)
	return
}

func (cdb *CertPG) Stream(ctx context.Context, ls *certstream.LogStream) (err error) {
	var b []byte
	if b, err = json.Marshal(ls.Log); err == nil {
		row := cdb.getStreamID.QueryRowContext(ctx, ls.URL, ls.LogOperator.Id, string(b))
		err = row.Scan(&ls.Id)
	}
	return
}

func (cdb *CertPG) GetMinMaxIndexes(ctx context.Context, streamUrl string) (minIndex, maxIndex int64, err error) {
	minIndex = -1
	maxIndex = -1
	streamUrl = strings.ReplaceAll(streamUrl, "'", "''")
	row := cdb.DB.QueryRowContext(ctx, fmt.Sprintf("SELECT id FROM %sstream WHERE url='%s';", TablePrefix, streamUrl))
	var streamId int32
	if err = row.Scan(&streamId); err == nil {
		row = cdb.DB.QueryRowContext(ctx, fmt.Sprintf("SELECT MIN(logindex), MAX(logindex) FROM %sentry WHERE stream=%v;", TablePrefix, streamId))
		err = row.Scan(&minIndex, &maxIndex)
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

func (cdb *CertPG) Entry(ctx context.Context, le *certstream.LogEntry) (err error) {
	if cert := le.Cert(); cert != nil {
		var seen time.Time
		var sig []byte

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
