package certstream

import _ "embed"

//go:embed assets/createschema.sql
var CreateSchema string

//go:embed assets/funcoperatorid.sql
var FunctionOperatorID string

//go:embed assets/funcstreamid.sql
var FunctionStreamID string

//go:embed assets/funcsetsince.sql
var FuncSetSince string

//go:embed assets/funcsubdomain.sql
var FuncSubdomain string

//go:embed assets/funcingestbatch.sql
var FuncIngestBatch string

const SelectMinIndex = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectMaxIndex = `SELECT MAX(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectMinIndexFrom = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1 AND logindex >= $2;`

const SelectFindGap = `SELECT start_gap, end_gap FROM CERTDB_findgap($1, $2, $3);`

const SelectBackfillIndex = `SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`

const UpdateBackfillIndex = `UPDATE CERTDB_stream SET backfill_logindex = $1 WHERE id = $2 AND backfill_logindex < $1;`

const SelectEstimate = `SELECT reltuples AS estimate FROM pg_class WHERE relname = $1;`
