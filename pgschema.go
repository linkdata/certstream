package certstream

import _ "embed"

//go:embed assets/proccreateschema.sql
var ProcedureCreateSchema string

//go:embed assets/funcoperatorid.sql
var FunctionOperatorID string

//go:embed assets/funcstreamid.sql
var FunctionStreamID string

//go:embed assets/funcname.sql
var FunctionName string

//go:embed assets/funcnewentry.sql
var FuncNewEntry string

//go:embed assets/procaddnewentry.sql
var ProcAddNewEntry string

//go:embed assets/selectgaps.sql
var SelectGaps string

const SelectMinIndex = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectMaxIndex = `SELECT MAX(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectDnsnameLike = `SELECT * FROM CERTDB_dnsnames WHERE dnsname LIKE $1;`

const SelectEstimate = `SELECT reltuples AS estimate FROM pg_class WHERE relname = $1;`
