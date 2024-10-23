package certdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"github.com/linkdata/certstream"
)

// Certdb integrates with sql.DB to manage certificate stream data
type Certdb struct {
	db             *sql.DB
	upsertOperator *sql.Stmt
	upsertStream   *sql.Stmt
	upsertCert     *sql.Stmt
}

func prepareStmt(perr *error, db *sql.DB, txt string) (stmt *sql.Stmt) {
	var err error
	if stmt, err = db.Prepare(txt); err != nil {
		*perr = errors.Join(*perr, err)
	}
	return
}

// New creates a Certdb and creates the needed tables and indices if they don't exist.
func New(ctx context.Context, db *sql.DB) (cdb *Certdb, err error) {
	if err = CreateSchema(ctx, db); err == nil {
		cdb = &Certdb{
			db:             db,
			upsertOperator: prepareStmt(&err, db, "SELECT 1"),
			upsertStream:   prepareStmt(&err, db, "SELECT 1"),
			upsertCert:     prepareStmt(&err, db, "SELECT 1"),
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
	return closeAll(cdb.upsertCert, cdb.upsertStream, cdb.upsertOperator)
}

func (cdb *Certdb) Insert(le *certstream.LogEntry) {
	tx, err := cdb.db.Begin()
	if err == nil {
		defer tx.Commit()
	}
	if err != nil {
		panic(fmt.Sprintf("Dnsql.DnsHistory: %v", err))
	}
}
