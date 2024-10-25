package certdb

import (
	"fmt"
	"strconv"
	"strings"
)

type TableInfo struct {
	Name       string
	ForeignKey string // column which references ForeignKey(id)
	Columns    []string
	Conflicts  []string // columns to conflict on
	HasId      bool
	Create     string
}

func (ti *TableInfo) ColumnsEqualArg() (equals []string) {
	for i := 0; i < len(ti.Columns); i++ {
		equals = append(equals, ti.Columns[i]+"="+"$"+strconv.Itoa(i+1))
	}
	return
}

func (ti *TableInfo) CreateStmt(flavor Dbflavor) string {
	tableName := TablePrefix + ti.Name
	replacer := strings.NewReplacer(
		"{TableName}", tableName,
		"{IdColumnConstraint}", IdColumnConstraint[flavor],
		"{AlterTableForeignKey}", AlterTableForeignKeySQL(flavor, ti.Name, ti.ForeignKey),
		"{Blob}", BlobType[flavor],
		"{Sig}", SigType[flavor],
		"{ConflictIndex}", fmt.Sprintf("CREATE UNIQUE INDEX IF NOT EXISTS %s_full_idx ON %s (%s);",
			tableName, tableName, strings.Join(ti.Conflicts, ",")),
	)
	return replacer.Replace(ti.Create)
}
