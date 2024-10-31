package certpg

import (
	"context"
	"database/sql"
	"strings"
)

func setPrefix(templ string) (s string) {
	replacer := strings.NewReplacer(
		"CERTDB_", TablePrefix,
	)
	s = replacer.Replace(templ)
	return
}

func CreateSchema(ctx context.Context, db *sql.DB) (err error) {
	if _, err = db.ExecContext(ctx, Initialize); err == nil {
		if _, err = db.ExecContext(ctx, setPrefix(TableOperator)); err == nil {
			if _, err = db.ExecContext(ctx, setPrefix(TableStream)); err == nil {
				if _, err = db.ExecContext(ctx, setPrefix(TableIdent)); err == nil {
					if _, err = db.ExecContext(ctx, setPrefix(TableCert)); err == nil {
						if _, err = db.ExecContext(ctx, setPrefix(TableEntry)); err == nil {
							if _, err = db.ExecContext(ctx, setPrefix(TableRDNSName)); err == nil {
								if _, err = db.ExecContext(ctx, setPrefix(ViewDNSName)); err == nil {
									if _, err = db.ExecContext(ctx, setPrefix(TableIPAddress)); err == nil {
										if _, err = db.ExecContext(ctx, setPrefix(TableEmail)); err == nil {
											if _, err = db.ExecContext(ctx, setPrefix(TableURI)); err == nil {
												_, err = db.ExecContext(ctx, setPrefix(ProcedureNewEntry))
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
