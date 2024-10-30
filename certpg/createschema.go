package certpg

import (
	"context"
	"database/sql"
	"strings"
)

func createStmt(templ string) (s string) {
	replacer := strings.NewReplacer(
		"CERTDB_", TablePrefix,
	)
	s = replacer.Replace(templ)
	return
}

func CreateSchema(ctx context.Context, db *sql.DB) (err error) {
	if _, err = db.ExecContext(ctx, Initialize); err == nil {
		if _, err = db.ExecContext(ctx, createStmt(TableOperator)); err == nil {
			if _, err = db.ExecContext(ctx, createStmt(TableStream)); err == nil {
				if _, err = db.ExecContext(ctx, createStmt(TableIdent)); err == nil {
					if _, err = db.ExecContext(ctx, createStmt(TableCert)); err == nil {
						if _, err = db.ExecContext(ctx, createStmt(TableEntry)); err == nil {
							if _, err = db.ExecContext(ctx, createStmt(TableRDNSName)); err == nil {
								if _, err = db.ExecContext(ctx, createStmt(ViewDNSName)); err == nil {
									if _, err = db.ExecContext(ctx, createStmt(TableIPAddress)); err == nil {
										if _, err = db.ExecContext(ctx, createStmt(TableEmail)); err == nil {
											if _, err = db.ExecContext(ctx, createStmt(TableURI)); err == nil {
												_, err = db.ExecContext(ctx, createStmt(ProcedureNewEntry))
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
