package certstream

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Scanner interface {
	Scan(dest ...any) error
}

type gap struct {
	start int64
	end   int64
}

// PgDB integrates with sql.DB to manage certificate stream data for a PostgreSQL database
type PgDB struct {
	*CertStream
	*pgxpool.Pool
	Pfx                   func(string) string // prefix replacer
	Workers               atomic.Int32
	funcOperatorID        string
	funcStreamID          string
	funcIngestBatch       string
	stmtSelectAllGaps     string
	stmtSelectMinIdx      string
	stmtSelectMaxIdx      string
	stmtSelectBackfillIdx string
	stmtUpdateBackfillIdx string
	mu                    sync.Mutex // protects following
	batchCh               []chan *LogEntry
	workerBits            int
	workerCount           int
	estimates             map[string]float64 // row count estimates
	newentrytime          time.Duration
	newentrycount         int64
	avgentrytime          time.Duration
}

func ensureSchema(ctx context.Context, db *pgxpool.Pool, pfx func(string) string) (err error) {
	if _, err = db.Exec(ctx, pfx(CreateSchema)); err == nil {
		if _, err = db.Exec(ctx, pfx(FunctionOperatorID)); err == nil {
			if _, err = db.Exec(ctx, pfx(FunctionStreamID)); err == nil {
				_, err = db.Exec(ctx, pfx(FuncIngestBatch))
			}
		}
	}
	return
}

// NewPgDB creates a PgDB and creates the needed tables and indices if they don't exist.
func NewPgDB(ctx context.Context, cs *CertStream) (cdb *PgDB, err error) {
	const callOperatorID = `SELECT CERTDB_operator_id($1,$2);`
	const callStreamID = `SELECT CERTDB_stream_id($1,$2,$3);`

	if cs.Config.PgAddr != "" {
		dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?pool_max_conns=%d&pool_max_conn_idle_time=1m",
			cs.Config.PgUser, cs.Config.PgPass, cs.Config.PgAddr, cs.Config.PgName, cs.Config.PgConns)
		if cs.Config.PgNoSSL {
			dsn += "&sslmode=disable"
		}
		var poolcfg *pgxpool.Config
		if poolcfg, err = pgxpool.ParseConfig(dsn); err == nil {
			poolcfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
			var pool *pgxpool.Pool
			if pool, err = pgxpool.NewWithConfig(ctx, poolcfg); err == nil {
				if err = pool.Ping(ctx); err == nil {
					cs.LogInfo("database", "addr", cs.Config.PgAddr, "name", cs.Config.PgName, "prefix", cs.Config.PgPrefix)
					pfx := func(s string) string { return strings.ReplaceAll(s, "CERTDB_", cs.Config.PgPrefix) }
					if err = ensureSchema(ctx, pool, pfx); err == nil {
						var pgversion string
						if cs.LogError(pool.QueryRow(ctx, `SELECT version();`).Scan(&pgversion), "postgres version") == nil {
							cs.LogInfo("postgres", "version", pgversion)
						}
						workerBits := min(8, max(1, cs.Config.PgWorkerBits))
						workerCount := 1 << workerBits
						batchChans := make([]chan *LogEntry, workerCount)
						for i := range batchChans {
							batchChans[i] = make(chan *LogEntry, (DbBatchSize*12)/10)
						}
						cdb = &PgDB{
							CertStream:            cs,
							Pool:                  pool,
							Pfx:                   pfx,
							funcOperatorID:        pfx(callOperatorID),
							funcStreamID:          pfx(callStreamID),
							funcIngestBatch:       pfx(`SELECT CERTDB_ingest_batch($1::jsonb);`),
							stmtSelectAllGaps:     pfx(SelectAllGaps),
							stmtSelectMinIdx:      pfx(SelectMinIndex),
							stmtSelectMaxIdx:      pfx(SelectMaxIndex),
							stmtSelectBackfillIdx: pfx(SelectBackfillIndex),
							stmtUpdateBackfillIdx: pfx(UpdateBackfillIndex),
							batchCh:               batchChans,
							workerBits:            workerBits,
							workerCount:           workerCount,
							estimates: map[string]float64{
								"cert":   0,
								"domain": 0,
								"entry":  0,
							},
						}
						cdb.refreshEstimates(ctx)
					}
				}
			}
		}
	}
	if cdb != nil {
		cs.LogInfo("database workers", "count", cdb.workerCount, "bits", cdb.workerBits)
	}
	return
}

func (cdb *PgDB) Close() {
	cdb.mu.Lock()
	chans := cdb.batchCh
	cdb.batchCh = nil
	cdb.mu.Unlock()
	for _, ch := range chans {
		if ch != nil {
			close(ch)
		}
	}
	cdb.Pool.Close()
}

func (cdb *PgDB) QueueUsage() (pct int) {
	cdb.mu.Lock()
	chans := cdb.batchCh
	cdb.mu.Unlock()
	totalLen := 0
	totalCap := 0
	for _, ch := range chans {
		if ch != nil {
			totalLen += len(ch)
			totalCap += cap(ch)
		}
	}
	if totalCap > 0 {
		pct = totalLen * 100 / totalCap
	}
	return
}

func (cdb *PgDB) getBatchCh(idx int) (ch chan *LogEntry) {
	cdb.mu.Lock()
	ch = cdb.batchCh[idx]
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) workerIndexFor(le *LogEntry) (idx int) {
	if cdb != nil && le != nil {
		if cert := le.Cert(); cert != nil && len(cert.Signature) > 0 {
			idx = int(cert.Signature[0] >> (8 - cdb.workerBits))
		}
	}
	return
}

func (cdb *PgDB) sendToBatcher(ctx context.Context, le *LogEntry) {
	if le != nil && ctx.Err() == nil {
		if ch := cdb.getBatchCh(cdb.workerIndexFor(le)); ch != nil {
			select {
			case <-ctx.Done():
			case ch <- le:
			}
		}
	}
}

func (cdb *PgDB) ensureOperator(ctx context.Context, lo *LogOperator) (err error) {
	if cdb != nil {
		row := cdb.QueryRow(ctx, cdb.funcOperatorID, lo.operator.Name, strings.Join(lo.operator.Email, ","))
		err = wrapErr(row.Scan(&lo.Id), cdb.funcOperatorID)
	}
	return
}

func (cdb *PgDB) ensureStream(ctx context.Context, ls *LogStream) (err error) {
	if cdb != nil {
		var b []byte
		if b, err = json.Marshal(ls.logInfo()); err == nil {
			row := cdb.QueryRow(ctx, cdb.funcStreamID, ls.URL(), ls.LogOperator.Id, string(b))
			err = wrapErr(row.Scan(&ls.Id), cdb.funcStreamID)
		}
	}
	return
}

func (cdb *PgDB) fillIdentity(ctx context.Context, id int, ident *JsonIdentity) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT id, organization, province, country FROM CERTDB_ident WHERE id=$1;`), id)
	var dbident PgIdent
	if err := cdb.LogError(ScanIdent(row, &dbident), "fillIdentity", "id", id); err == nil {
		ident.ID = id
		ident.Country = dbident.Country
		ident.Organization = dbident.Organization
		ident.Province = dbident.Province
	}
}

func (cdb *PgDB) getCertStrings(ctx context.Context, id int64, tablename, colname string) (sl []string) {
	rows, err := cdb.Query(ctx, cdb.Pfx(fmt.Sprintf("SELECT %s::text FROM CERTDB_%s WHERE cert=$1;", colname, tablename)), id)
	if cdb.LogError(err, "getCertStrings/"+tablename, "id", id) == nil {
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := cdb.LogError(rows.Scan(&s), "getCertStrings/scan/"+tablename); err == nil {
				sl = append(sl, s)
			}
		}
	}
	return
}

func (cdb *PgDB) getCertificate(ctx context.Context, dbcert *PgCertificate) (cert *JsonCertificate, err error) {
	cert = &JsonCertificate{
		PreCert:        dbcert.PreCert,
		Signature:      dbcert.Sha256,
		CommonName:     dbcert.CommonName,
		DNSNames:       []string{},
		EmailAddresses: []string{},
		IPAddresses:    []string{},
		URIs:           []string{},
		NotBefore:      dbcert.NotBefore,
		NotAfter:       dbcert.NotAfter,
		Since:          dbcert.Since,
	}
	cdb.fillIdentity(ctx, dbcert.IssuerID, &cert.Issuer)
	cdb.fillIdentity(ctx, dbcert.SubjectID, &cert.Subject)
	cert.Subject.CommonName = dbcert.CommonName
	cert.DNSNames = cdb.getCertStrings(ctx, dbcert.Id, "dnsnames", "fqdn")
	cert.EmailAddresses = cdb.getCertStrings(ctx, dbcert.Id, "email", "email")
	cert.IPAddresses = cdb.getCertStrings(ctx, dbcert.Id, "ipaddress", "addr")
	for i := range cert.IPAddresses {
		cert.IPAddresses[i] = strings.TrimSuffix(cert.IPAddresses[i], "/32")
	}
	cert.URIs = cdb.getCertStrings(ctx, dbcert.Id, "uri", "uri")
	cert.SetCommonName()
	return
}

func (cdb *PgDB) GetCertificateByLogEntry(ctx context.Context, entry *PgLogEntry) (cert *JsonCertificate, err error) {
	return cdb.GetCertificateByID(ctx, entry.CertID)
}

func RenderSQL(query string, args ...any) string {
	for i, arg := range args {
		var s string
		switch v := arg.(type) {
		case string:
			s = fmt.Sprintf("'%s'", strings.ReplaceAll(v, "'", "''"))
		case time.Time:
			s = fmt.Sprintf("'%s'", v.Format(time.RFC3339))
		default:
			s = fmt.Sprint(v)
		}
		query = strings.ReplaceAll(query, fmt.Sprintf("$%d", i+1), s)
	}
	return query
}

func (cdb *PgDB) GetCertificatesByCommonName(ctx context.Context, commonname string) (certs []*JsonCertificate, err error) {
	var rows pgx.Rows
	if rows, err = cdb.Query(ctx, cdb.Pfx(`SELECT id, notbefore, notafter, commonname, subject, issuer, sha256, precert, since FROM CERTDB_cert WHERE commonname=$1 ORDER BY notbefore DESC;`), commonname); err == nil {
		defer rows.Close()
		for rows.Next() {
			var dbcert PgCertificate
			e := ScanCertificate(rows, &dbcert)
			if e == nil {
				var cert *JsonCertificate
				if cert, e = cdb.getCertificate(ctx, &dbcert); e == nil {
					certs = append(certs, cert)
				}
			}
			err = errors.Join(err, e)
		}
		err = errors.Join(err, rows.Err())
	}
	return
}

func (cdb *PgDB) GetCertificateByHash(ctx context.Context, hash []byte) (cert *JsonCertificate, err error) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT id, notbefore, notafter, commonname, subject, issuer, sha256, precert, since FROM CERTDB_cert WHERE sha256=$1;`), hash)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}

func (cdb *PgDB) GetCertificateByID(ctx context.Context, id int64) (cert *JsonCertificate, err error) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT id, notbefore, notafter, commonname, subject, issuer, sha256, precert, since FROM CERTDB_cert WHERE id=$1;`), id)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}

func (cdb *PgDB) GetHistoricalCertificates(ctx context.Context, expiresAfter time.Time, callback func(ctx context.Context, cert *JsonCertificate) (err error)) (err error) {
	if cdb != nil {
		expiresAfter = expiresAfter.UTC()
		var maxNotAfter *time.Time
		if err = cdb.QueryRow(ctx, cdb.Pfx(`SELECT MAX(notafter) FROM CERTDB_cert;`)).Scan(&maxNotAfter); err == nil {
			if maxNotAfter != nil {
				maxAtStart := maxNotAfter.UTC()
				pageSize := DbBatchSize
				if pageSize < 1 {
					pageSize = 100
				}
				lastNotAfter := expiresAfter
				lastID := int64(0)
				query := cdb.Pfx(`
SELECT id, notbefore, notafter, commonname, subject, issuer, sha256, precert, since
FROM CERTDB_cert
WHERE notafter > $1
  AND notafter <= $2
  AND (notafter > $3 OR (notafter = $3 AND id > $4))
ORDER BY notafter ASC, id ASC
LIMIT $5;
`)
				for err == nil {
					var rows pgx.Rows
					if rows, err = cdb.Query(ctx, query, expiresAfter, maxAtStart, lastNotAfter, lastID, pageSize); err == nil {
						var dbcerts []PgCertificate
						for rows.Next() && err == nil {
							var dbcert PgCertificate
							if err = ScanCertificate(rows, &dbcert); err == nil {
								dbcerts = append(dbcerts, dbcert)
							}
						}
						if err == nil {
							err = rows.Err()
						}
						rows.Close()
						if err == nil {
							if len(dbcerts) == 0 {
								break
							}
							for i := range dbcerts {
								if err == nil {
									dbcert := dbcerts[i]
									var cert *JsonCertificate
									if cert, err = cdb.getCertificate(ctx, &dbcert); err == nil {
										if err = callback(ctx, cert); err == nil {
											lastNotAfter = dbcert.NotAfter
											lastID = dbcert.Id
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

func (cdb *PgDB) DeleteCertificates(ctx context.Context, cutoff time.Time, batchSize int) (rowsDeleted int64, err error) {
	if cdb != nil {
		if batchSize > 0 {
			cutoff = cutoff.UTC()
			query := cdb.Pfx(`WITH todelete AS (
  SELECT ctid
  FROM CERTDB_cert
  WHERE notafter <= $1
  ORDER BY notafter DESC
  LIMIT $2
)
DELETE FROM CERTDB_cert
USING todelete
WHERE CERTDB_cert.ctid = todelete.ctid;`)
			var tag pgconn.CommandTag
			if tag, err = cdb.Exec(ctx, query, cutoff, batchSize); err == nil {
				rowsDeleted = tag.RowsAffected()
			}
		}
	}
	return
}

func (cdb *PgDB) DeleteStream(ctx context.Context, streamId int32, batchSize int) (rowsDeleted int64, err error) {
	if cdb != nil {
		if batchSize > 0 {
			query := cdb.Pfx(`WITH todelete AS (
  SELECT logindex
  FROM CERTDB_entry
  WHERE stream = $1
  ORDER BY logindex ASC
  LIMIT $2
)
DELETE FROM CERTDB_entry
USING todelete
WHERE CERTDB_entry.stream = $1
  AND CERTDB_entry.logindex = todelete.logindex;`)
			var tag pgconn.CommandTag
			if tag, err = cdb.Exec(ctx, query, streamId, batchSize); err == nil {
				rowsDeleted = tag.RowsAffected()
				if rowsDeleted == 0 {
					if tag, err = cdb.Exec(ctx, cdb.Pfx(`DELETE FROM CERTDB_stream WHERE id = $1;`), streamId); err == nil {
						rowsDeleted = tag.RowsAffected()
					}
				}
			}
		}
	}
	return
}

func (cdb *PgDB) Estimate(table string) (f float64) {
	table = strings.TrimPrefix(table, "CERTDB_")
	table = strings.TrimPrefix(table, cdb.CertStream.Config.PgPrefix)
	cdb.mu.Lock()
	f = cdb.estimates[table]
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) refreshEstimatesBatch() (batch *pgx.Batch) {
	batch = &pgx.Batch{}
	cdb.mu.Lock()
	defer cdb.mu.Unlock()
	for k := range cdb.estimates {
		table := cdb.Pfx("CERTDB_" + k)
		batch.Queue(SelectEstimate, table).QueryRow(func(row pgx.Row) error {
			var estimate float64
			if cdb.LogError(row.Scan(&estimate), "refreshEstimates", "table", table) == nil {
				cdb.mu.Lock()
				cdb.estimates[k] = estimate
				cdb.mu.Unlock()
			}
			return nil
		})
	}
	return
}

func (cdb *PgDB) refreshEstimates(ctx context.Context) {
	if batch := cdb.refreshEstimatesBatch(); batch != nil {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		_ = cdb.LogError(cdb.SendBatch(ctx, batch).Close(), "refreshEstimates")
	}
}

func (cdb *PgDB) estimator(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cdb.refreshEstimates(ctx)
		}
	}
}

type gapTotals struct {
	count atomic.Int64
	size  atomic.Int64
}

func (gt *gapTotals) add(g gap) {
	if gt != nil {
		gt.count.Add(1)
		gt.size.Add((g.end - g.start) + 1)
	}
}

func (gt *gapTotals) values() (count int64, size int64) {
	if gt != nil {
		count = gt.count.Load()
		size = gt.size.Load()
	}
	return
}

func gapLogIndexLabel(logIndex int64) (label string) {
	label = strconv.FormatInt(logIndex, 10)
	if strings.HasPrefix(label, "-") {
		label = "neg" + strings.TrimPrefix(label, "-")
	}
	return
}

func (cdb *PgDB) selectAllGapsStmt(streamID int32, logIndex int64) (stmt string) {
	if cdb != nil {
		stmt = cdb.stmtSelectAllGaps
		if stmt != "" {
			stmt = strings.ReplaceAll(stmt, "STREAMID", strconv.FormatInt(int64(streamID), 10))
			stmt = strings.ReplaceAll(stmt, "LOGINDEX", gapLogIndexLabel(logIndex))
		}
	}
	return
}

func (cdb *PgDB) selectStreamGaps(ctx context.Context, wg *sync.WaitGroup, ls *LogStream, pageSize int, totals *gapTotals) {
	defer wg.Done()

	if ls != nil {
		gapCh := ls.getGapCh()
		if gapCh != nil {
			if pageSize > 0 {
				var err error
				var maxIndex sql.NullInt64
				if err = cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id).Scan(&maxIndex); err == nil {
					endIndex := int64(-1)
					if maxIndex.Valid {
						endIndex = maxIndex.Int64
					}
					if endIndex >= 0 {
						var lastIndex int64 = -1
						for err == nil && ctx.Err() == nil && lastIndex < endIndex {
							stmt := cdb.selectAllGapsStmt(ls.Id, lastIndex)
							row := cdb.QueryRow(ctx, stmt, ls.Id, lastIndex, endIndex, pageSize)
							var gapStart sql.NullInt64
							var gapEnd sql.NullInt64
							var lastLogIndex sql.NullInt64
							if err = row.Scan(&gapStart, &gapEnd, &lastLogIndex); err == nil {
								advanced := false
								if gapStart.Valid && gapEnd.Valid {
									g := gap{start: gapStart.Int64, end: gapEnd.Int64}
									select {
									case <-ctx.Done():
									case gapCh <- g:
										lastIndex = gapEnd.Int64
										if totals != nil {
											totals.add(g)
										}
										advanced = true
									}
								}
								if !advanced && ctx.Err() == nil && lastLogIndex.Valid {
									if lastLogIndex.Int64 > lastIndex {
										lastIndex = lastLogIndex.Int64
										advanced = true
									}
								}
								if !advanced {
									break
								}
							}
						}
					}
				}
				_ = cdb.LogError(err, "selectAllGaps.stream", "stream", ls.Id, "url", ls.URL())
			}
		}
	}
}

func (cdb *PgDB) selectAllGaps(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	streams := make(map[int32]*LogStream)

	cdb.mu.Lock()
	for _, logop := range cdb.operators {
		logop.mu.Lock()
		for _, ls := range logop.streams {
			if ls.gapCh == nil {
				ls.gapCh = make(chan gap, 1)
			}
			streams[ls.Id] = ls
		}
		logop.mu.Unlock()
	}
	cdb.mu.Unlock()

	defer func() {
		for _, ls := range streams {
			ls.mu.Lock()
			if ls.gapCh != nil {
				close(ls.gapCh)
				ls.gapCh = nil
			}
			ls.mu.Unlock()
		}
	}()

	start := time.Now()
	cdb.LogInfo("selectAllGaps starts", "streams", len(streams))

	var totals gapTotals
	if ctx.Err() == nil {
		pageSize := DbBatchSize
		if pageSize < 100 {
			pageSize = 100
		}
		if pageSize > 10000 {
			pageSize = 10000
		}

		var streamWG sync.WaitGroup
		for _, ls := range streams {
			streamWG.Add(1)
			go cdb.selectStreamGaps(ctx, &streamWG, ls, pageSize, &totals)
		}
		streamWG.Wait()
	}

	if ctx.Err() == nil {
		totalgaps, totalgapsize := totals.values()
		cdb.LogInfo("selectAllGaps completed", "totalgapsize", totalgapsize, "totalgaps", totalgaps, "elapsed", time.Since(start).Round(time.Second))
	}
}
