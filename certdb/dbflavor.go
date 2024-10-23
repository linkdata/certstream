package certdb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type Dbflavor int

const (
	FlavorUnknown = Dbflavor(iota)
	FlavorPostgreSQL
	FlavorSQLite
	FlavorMySQL
)

var IdColumnConstraint = map[Dbflavor]string{
	FlavorUnknown:    "PRIMARY KEY",
	FlavorPostgreSQL: "PRIMARY KEY GENERATED ALWAYS AS IDENTITY",
	FlavorSQLite:     "PRIMARY KEY",
	FlavorMySQL:      "PRIMARY KEY AUTO_INCREMENT",
}

func AlterTableForeignKeySQL(flavor Dbflavor, table, fk string) string {
	if table != "" && fk != "" {
		switch flavor {
		case FlavorMySQL, FlavorPostgreSQL:
			constraintname := fmt.Sprintf("fk_%s_%s", TablePrefix+table, fk)
			return fmt.Sprintf(
				`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s; ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (id);`,
				TablePrefix+table, constraintname,
				TablePrefix+table, constraintname, fk, TablePrefix+fk)
		}
	}
	return ""
}

func GetDbflavor(ctx context.Context, db *sql.DB) Dbflavor {
	var versionstring string
	var one int
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&versionstring); err == nil && strings.Contains(versionstring, "PostgreSQL") {
		return FlavorPostgreSQL
	}
	if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&versionstring); err == nil && versionstring != "" {
		return FlavorSQLite
	}
	if err := db.QueryRowContext(ctx, "SELECT SQL_NO_CACHE 1").Scan(&one); err == nil && one == 1 {
		return FlavorMySQL
	}
	return FlavorUnknown
}
