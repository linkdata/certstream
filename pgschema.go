package certstream

import _ "embed"

// CreateSchema contains SQL to apply the CertDB schema.
//
// Existing tables remain unchanged. New databases receive B-tree domain
// indexes and no trigram index. It removes the CERTDB_gap type,
// CERTDB_findgap function, and CERTDB_set_backfill_first_gap procedure.
//
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

// FuncIngestBatch contains SQL to install the certificate ingest functions.
//
// [NewPgDB] installs these functions when opening the database.
//
//go:embed assets/funcingestbatch.sql
var FuncIngestBatch string

const SelectMinIndex = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectMaxIndex = `SELECT MAX(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`

const SelectMinIndexFrom = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1 AND logindex >= $2;`

const selectGapWindow = `SELECT /* CERTDB_gap_window */ logindex FROM CERTDB_entry WHERE stream = $1 AND logindex BETWEEN $2 AND $3 ORDER BY logindex;` // #nosec G101 -- this is a SQL query, not a credential

const SelectBackfillIndex = `SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`

const UpdateBackfillIndex = `UPDATE CERTDB_stream SET backfill_logindex = $1 WHERE id = $2 AND backfill_logindex < $1;`

const lowerBackfillIndex = `UPDATE CERTDB_stream SET backfill_logindex = $1 WHERE id = $2 AND backfill_logindex > $1;`

const SelectEstimate = `SELECT reltuples AS estimate FROM pg_class WHERE relname = $1;`
