package certpg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/linkdata/certstream"
)

// CertPG integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type CertPG struct {
	db              *sql.DB
	upsertOperator  *sql.Stmt
	upsertStream    *sql.Stmt
	upsertIdent     *sql.Stmt
	upsertCert      *sql.Stmt
	upsertEntry     *sql.Stmt
	upsertRDNSname  *sql.Stmt
	upsertIPAddress *sql.Stmt
	upsertEmail     *sql.Stmt
	upsertURI       *sql.Stmt
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
		fmt.Println(txt, err)
		*perr = errors.Join(*perr, err)
	}
	return
}

// New creates a Certdb and creates the needed tables and indices if they don't exist.
func New(ctx context.Context, db *sql.DB) (cdb *CertPG, err error) {
	if err = CreateSchema(ctx, db); err == nil {
		cdb = &CertPG{
			db:             db,
			upsertOperator: prepareUpsert(&err, db, "operator", true, []string{"name", "email"}, nil),
			upsertStream:   prepareUpsert(&err, db, "stream", true, []string{"url"}, []string{"operator", "lastindex", "json"}),
			upsertIdent:    prepareUpsert(&err, db, "ident", true, []string{"organization", "province", "country"}, nil),
			upsertCert: prepareUpsert(&err, db, "cert", true, []string{"sha256"},
				[]string{
					"commonname",
					"subject",
					"issuer",
					"notbefore",
					"notafter",
				},
			),
			upsertEntry:     prepareUpsert(&err, db, "entry", false, []string{"stream", "index"}, []string{"cert"}),
			upsertRDNSname:  prepareUpsert(&err, db, "rdnsname", false, []string{"cert", "rname"}, nil),
			upsertIPAddress: prepareUpsert(&err, db, "ipaddress", false, []string{"cert", "addr"}, nil),
			upsertEmail:     prepareUpsert(&err, db, "email", false, []string{"cert", "email"}, nil),
			upsertURI:       prepareUpsert(&err, db, "uri", false, []string{"cert", "uri"}, nil),
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

// Close frees resources used.
func (cdb *CertPG) Close() error {
	return closeAll(
		cdb.upsertOperator,
		cdb.upsertStream,
		cdb.upsertIdent,
		cdb.upsertCert,
		cdb.upsertEntry,
		cdb.upsertRDNSname,
		cdb.upsertIPAddress,
		cdb.upsertEmail,
		cdb.upsertURI,
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
		row := cdb.upsertStream.QueryRowContext(ctx, ls.URL, ls.LogOperator.Id, ls.Index, string(b))
		err = row.Scan(&ls.Id)
	}
	return
}

func (cdb *CertPG) Entry(ctx context.Context, le *certstream.LogEntry) (err error) {
	cert := le.Cert()
	var tx *sql.Tx
	if tx, err = cdb.db.Begin(); err == nil {
		defer func() {
			if err != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}()
		var sig []byte
		if sig = cert.Signature; len(sig) != 16 {
			shasig := sha256.Sum256(le.RawLogEntry.Cert.Data)
			sig = shasig[:]
		}

		row := tx.StmtContext(ctx, cdb.upsertIdent).QueryRowContext(ctx,
			strings.Join(cert.Issuer.Organization, ","),
			strings.Join(cert.Issuer.Province, ","),
			strings.Join(cert.Issuer.Country, ","),
		)
		var issuerId int64
		if err = row.Scan(&issuerId); err != nil {
			return
		}

		row = tx.StmtContext(ctx, cdb.upsertIdent).QueryRowContext(ctx,
			strings.Join(cert.Subject.Organization, ","),
			strings.Join(cert.Subject.Province, ","),
			strings.Join(cert.Subject.Country, ","),
		)
		var subjectId int64
		if err = row.Scan(&subjectId); err != nil {
			return
		}

		row = tx.StmtContext(ctx, cdb.upsertCert).QueryRowContext(ctx,
			sig,
			cert.Subject.CommonName,
			subjectId,
			issuerId,
			cert.NotBefore,
			cert.NotAfter,
		)
		var certId int64
		if err = row.Scan(&certId); err != nil {
			return
		}
		if _, err = tx.StmtContext(ctx, cdb.upsertEntry).ExecContext(ctx, le.LogStream.Id, le.Index(), certId); err != nil {
			return
		}
		for _, dnsname := range cert.DNSNames {
			if parts := strings.Split(strings.ToLower(dnsname), "."); len(parts) > 0 {
				if parts[0] == "*" {
					parts[0] = "STAR"
				}
				slices.Reverse(parts)
				if _, err = tx.StmtContext(ctx, cdb.upsertRDNSname).ExecContext(ctx, certId, strings.Join(parts, ".")); err != nil {
					return
				}
			}
		}
		for _, ip := range cert.IPAddresses {
			if _, err = tx.StmtContext(ctx, cdb.upsertIPAddress).ExecContext(ctx, certId, ip.String()); err != nil {
				return
			}
		}
		for _, email := range cert.EmailAddresses {
			if _, err = tx.StmtContext(ctx, cdb.upsertEmail).ExecContext(ctx, certId, email); err != nil {
				return
			}
		}
		for _, uri := range cert.URIs {
			if _, err = tx.StmtContext(ctx, cdb.upsertURI).ExecContext(ctx, certId, uri); err != nil {
				return
			}
		}
	}
	return
}
