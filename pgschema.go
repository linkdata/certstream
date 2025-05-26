package certstream

import _ "embed"

//go:embed assets/createschema.sql
var CreateSchema string

//go:embed assets/funcoperatorid.sql
var FunctionOperatorID string

//go:embed assets/funcstreamid.sql
var FunctionStreamID string

//go:embed assets/funcfindsince.sql
var FunctionFindSince string

//go:embed assets/procaddnewentry.sql
var ProcAddNewEntry string

//go:embed assets/selectgaps.sql
var SelectGaps string

//go:embed assets/selectidsince.sql
var SelectIDSince string

const SelectMinIndex = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectMaxIndex = `SELECT MAX(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectDnsnameLike = `SELECT * FROM CERTDB_domain WHERE domain LIKE $1;`

const SelectEstimate = `SELECT reltuples AS estimate FROM pg_class WHERE relname = $1;`
