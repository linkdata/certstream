package certpg

import _ "embed"

//go:embed proccreateschema.sql
var ProcedureCreateSchema string

//go:embed funcoperatorid.sql
var FunctionOperatorID string

//go:embed funcstreamid.sql
var FunctionStreamID string

//go:embed procnewentry.sql
var ProcedureNewEntry string

//go:embed selectgaps.sql
var SelectGaps string

const SelectMinIndex = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectMaxIndex = `SELECT MAX(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`
