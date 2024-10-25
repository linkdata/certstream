package certdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/linkdata/certstream"
)

// Certdb integrates with sql.DB to manage certificate stream data
type Certdb struct {
	db              *sql.DB
	upsertOperator  *sql.Stmt
	upsertStream    *sql.Stmt
	upsertCert      *sql.Stmt
	upsertEntry     *sql.Stmt
	upsertDNSname   *sql.Stmt
	upsertIPAddress *sql.Stmt
	upsertEmail     *sql.Stmt
	upsertURI       *sql.Stmt
}

func prepareUpsert(perr *error, db *sql.DB, flavor Dbflavor, ti *TableInfo) (stmt *sql.Stmt) {
	var err error
	txt := UpsertSQL(flavor, ti)
	if stmt, err = db.Prepare(txt); err != nil {
		fmt.Println(txt, err)
		*perr = errors.Join(*perr, err)
	}
	return
}

// New creates a Certdb and creates the needed tables and indices if they don't exist.
func New(ctx context.Context, db *sql.DB) (cdb *Certdb, err error) {
	flavor := GetDbflavor(ctx, db)
	if err = CreateSchema(ctx, db, flavor); err == nil {
		cdb = &Certdb{
			db:              db,
			upsertOperator:  prepareUpsert(&err, db, flavor, TableOperator),
			upsertStream:    prepareUpsert(&err, db, flavor, TableStream),
			upsertCert:      prepareUpsert(&err, db, flavor, TableCert),
			upsertEntry:     prepareUpsert(&err, db, flavor, TableEntry),
			upsertDNSname:   prepareUpsert(&err, db, flavor, TableDNSName),
			upsertIPAddress: prepareUpsert(&err, db, flavor, TableIPAddress),
			upsertEmail:     prepareUpsert(&err, db, flavor, TableEmail),
			upsertURI:       prepareUpsert(&err, db, flavor, TableURI),
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
func (cdb *Certdb) Close() error {
	return closeAll(
		cdb.upsertOperator,
		cdb.upsertStream,
		cdb.upsertCert,
		cdb.upsertEntry,
		cdb.upsertDNSname,
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

func (cdb *Certdb) Operator(ctx context.Context, lo *certstream.LogOperator) (err error) {
	row := cdb.upsertOperator.QueryRowContext(ctx, lo.Name, strings.Join(lo.Email, ","))
	err = row.Scan(&lo.Id)
	return
}

func (cdb *Certdb) Stream(ctx context.Context, ls *certstream.LogStream) (err error) {
	var b []byte
	if b, err = json.Marshal(ls.Log); err == nil {
		row := cdb.upsertStream.QueryRowContext(ctx, ls.URL, ls.LogOperator.Id, ls.Index, string(b))
		err = row.Scan(&ls.Id)
	}
	return
}

func (cdb *Certdb) Entry(ctx context.Context, le *certstream.LogEntry) (err error) {
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
		if sig = cert.Signature; len(sig) == 0 {
			shasig := sha256.Sum256(cert.RawTBSCertificate)
			sig = shasig[:]
		}
		if len(sig) > 32 {
			shasig := sha256.Sum256(cert.Raw)
			sig = shasig[:]
		}
		row := tx.StmtContext(ctx, cdb.upsertCert).QueryRowContext(ctx,
			hex.EncodeToString(sig),
			cert.NotBefore,
			cert.NotAfter,
			strings.Join(cert.Subject.Organization, ","),
			strings.Join(cert.Subject.Province, ","),
			strings.Join(cert.Subject.Country, ","),
		)
		var certId int64
		if err = row.Scan(&certId); err == nil {
			if _, err = tx.StmtContext(ctx, cdb.upsertEntry).ExecContext(ctx, le.LogStream.Id, le.Index(), certId); err == nil {
				for _, dnsname := range cert.DNSNames {
					parts := strings.Split(dnsname, ".")
					slices.Reverse(parts)
					if _, err = tx.StmtContext(ctx, cdb.upsertDNSname).ExecContext(ctx, certId, dnsname, strings.Join(parts, ".")); err != nil {
						return
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
		}
	}
	return
}
