package certpg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/linkdata/certstream"
)

// CertPG integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type CertPG struct {
	*sql.DB
	certstream.Logger
	upsertOperator *sql.Stmt
	upsertStream   *sql.Stmt
	procNewEntry   *sql.Stmt
}

func UpsertSQL(table string, hasid bool, keycols, datacols []string) (stmt string) {
	var dollarargs []string
	var assignments []string
	var columns []string
	columns = append(columns, keycols...)
	columns = append(columns, datacols...)
	for i := 0; i < len(columns); i++ {
		dollararg := "$" + strconv.Itoa(i+1)
		dollarargs = append(dollarargs, dollararg)
		assignments = append(assignments, columns[i]+"="+dollararg)
	}
	stmt = fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, TablePrefix+table, strings.Join(columns, ","), strings.Join(dollarargs, ","))
	if len(keycols) > 0 {
		stmt += fmt.Sprintf(` ON CONFLICT (%s) DO UPDATE SET %s`, strings.Join(keycols, ","), strings.Join(assignments, ","))
	}
	if hasid {
		stmt += ` RETURNING id`
	}
	return
}

func prepareUpsert(perr *error, db *sql.DB, table string, hasid bool, keycols, datacols []string) (stmt *sql.Stmt) {
	var err error
	txt := UpsertSQL(table, hasid, keycols, datacols)
	if stmt, err = db.Prepare(txt); err != nil {
		*perr = errors.Join(*perr, fmt.Errorf("%q: %v", txt, err))
	}
	return
}

func prepareNewEntry(perr *error, db *sql.DB) (stmt *sql.Stmt) {
	var err error
	txt := fmt.Sprintf(`CALL %snew_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16);`, TablePrefix)
	if stmt, err = db.Prepare(txt); err != nil {
		*perr = errors.Join(*perr, fmt.Errorf("%q: %v", txt, err))
	}
	return
}

// New creates a Certdb and creates the needed tables and indices if they don't exist.
func New(ctx context.Context, db *sql.DB) (cdb *CertPG, err error) {
	if err = CreateSchema(ctx, db); err == nil {
		cdb = &CertPG{
			DB:             db,
			upsertOperator: prepareUpsert(&err, db, "operator", true, []string{"name", "email"}, nil),
			upsertStream:   prepareUpsert(&err, db, "stream", true, []string{"url"}, []string{"operator", "json"}),
			procNewEntry:   prepareNewEntry(&err, db),
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
		cdb.upsertOperator,
		cdb.upsertStream,
		cdb.procNewEntry,
	)
}

func dbRes(res sql.Result) string {
	rowId, _ := res.LastInsertId()
	numRows, _ := res.RowsAffected()
	return fmt.Sprintf("rowId=%v numRows=%v", rowId, numRows)
}

func (cdb *CertPG) Operator(ctx context.Context, lo *certstream.LogOperator) (err error) {
	row := cdb.upsertOperator.QueryRowContext(ctx, lo.Name, strings.Join(lo.Email, ","))
	err = row.Scan(&lo.Id)
	return
}

func (cdb *CertPG) Stream(ctx context.Context, ls *certstream.LogStream) (err error) {
	var b []byte
	if b, err = json.Marshal(ls.Log); err == nil {
		row := cdb.upsertStream.QueryRowContext(ctx, ls.URL, ls.LogOperator.Id, string(b))
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
		logindex := le.Index()

		var sig []byte
		if sig = cert.Signature; len(sig) != 16 {
			if le.RawLogEntry != nil {
				shasig := sha256.Sum256(le.RawLogEntry.Cert.Data)
				sig = shasig[:]
			} else {
				shasig := sha256.Sum256(cert.RawTBSCertificate)
				sig = shasig[:]
			}
		}

		var dnsnames []string
		for _, dnsname := range cert.DNSNames {
			dnsnames = append(dnsnames, strings.ToLower(dnsname))
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
				fmt.Printf("CALL CERTDB_new_entry(%v,%v,'%x', '%s','%s','%s', '%s','%s','%s', '%s','%s', '%s', '%s','%s','%s','%s')\n", args...)
			}
		}
	}
	return
}
