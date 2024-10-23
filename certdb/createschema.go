package certdb

import (
	"context"
	"database/sql"
)

func CreateSchema(ctx context.Context, db *sql.DB) (err error) {
	flavor := GetDbflavor(ctx, db)
	if _, err = db.ExecContext(ctx, TableOperator.CreateStmt(flavor)); err == nil {
		if _, err = db.ExecContext(ctx, TableStream.CreateStmt(flavor)); err == nil {
			if _, err = db.ExecContext(ctx, TableCert.CreateStmt(flavor)); err == nil {
				if _, err = db.ExecContext(ctx, TableDNSName.CreateStmt(flavor)); err == nil {
					if _, err = db.ExecContext(ctx, TableIPAddress.CreateStmt(flavor)); err == nil {
						if _, err = db.ExecContext(ctx, TableEmail.CreateStmt(flavor)); err == nil {
							_, err = db.ExecContext(ctx, URITable.CreateStmt(flavor))
						}
					}
				}
			}
		}
	}
	return
}
