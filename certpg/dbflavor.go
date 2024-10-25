package certdb

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
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

var BlobType = map[Dbflavor]string{
	FlavorUnknown:    "BLOB",
	FlavorPostgreSQL: "BYTEA",
	FlavorSQLite:     "BLOB",
	FlavorMySQL:      "BLOB",
}

var SigType = map[Dbflavor]string{
	FlavorUnknown:    "VARBINARY(32)",
	FlavorPostgreSQL: "BYTEA",
	FlavorSQLite:     "BLOB",
	FlavorMySQL:      "VARBINARY(32)",
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
