package certdb

import "strings"

type TableInfo struct {
	Name       string
	ForeignKey string // column which references ForeignKey(id)
	Create     string
	Upsert     string
}

func (ti *TableInfo) CreateStmt(flavor Dbflavor) string {
	replacer := strings.NewReplacer(
		"{TableName}", TablePrefix+ti.Name,
		"{IdColumnConstraint}", IdColumnConstraint[flavor],
		"{AlterTableForeignKey}", AlterTableForeignKeySQL(flavor, ti.Name, ti.ForeignKey),
	)
	return replacer.Replace(ti.Create)
}
