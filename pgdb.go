package certstream

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
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

func (cdb *PgDB) gapIndexWorkers(total int) (workers int) {
	workers = 1
	if cdb != nil {
		if cdb.CertStream != nil {
			workers = cdb.CertStream.Config.PgConns / 4
		}
		if workers < 1 {
			workers = 1
		}
		if workers > 16 {
			workers = 16
		}
	}
	if total < workers {
		workers = total
	}
	return
}

func (cdb *PgDB) selectGapEndIndexes(ctx context.Context, streamIDs []int32) (endIndexes map[int32]int64, err error) {
	endIndexes = map[int32]int64{}
	if len(streamIDs) > 0 {
		query := cdb.Pfx(`SELECT logindex FROM CERTDB_entry WHERE stream = $1 ORDER BY logindex DESC LIMIT 1;`)
		workers := cdb.gapIndexWorkers(len(streamIDs))
		if workers < 1 {
			workers = 1
		}
		type result struct {
			streamID int32
			maxIndex int64
			ok       bool
			err      error
		}
		sem := make(chan struct{}, workers)
		results := make(chan result, len(streamIDs))
		var wg sync.WaitGroup
		for _, streamID := range streamIDs {
			if ctx.Err() == nil {
				wg.Add(1)
				sem <- struct{}{}
				go func(id int32) {
					defer wg.Done()
					defer func() {
						<-sem
					}()
					row := cdb.QueryRow(ctx, query, id)
					var maxIndex int64
					e := row.Scan(&maxIndex)
					if e == nil {
						results <- result{streamID: id, maxIndex: maxIndex, ok: true}
					} else if errors.Is(e, pgx.ErrNoRows) {
						results <- result{streamID: id}
					} else {
						results <- result{streamID: id, err: e}
					}
				}(streamID)
			}
		}
		go func() {
			wg.Wait()
			close(results)
		}()
		for res := range results {
			if res.err == nil {
				if res.ok {
					endIndexes[res.streamID] = res.maxIndex
				}
			} else {
				err = errors.Join(err, res.err)
			}
		}
	}
	return
}

func (cdb *PgDB) enqueueGap(ctx context.Context, gapCh chan gap, queue *[]gap, g gap) (cancelled bool) {
	if gapCh != nil {
		select {
		case <-ctx.Done():
			cancelled = true
		case gapCh <- g:
		default:
			if queue != nil {
				*queue = append(*queue, g)
			}
		}
	}
	if ctx.Err() != nil {
		cancelled = true
	}
	return
}

func (cdb *PgDB) flushGapQueue(ctx context.Context, gapCh chan gap, queue []gap) (cancelled bool) {
	if gapCh != nil {
		remain := len(queue)
		idx := 0
		for remain > 0 && ctx.Err() == nil {
			sent := false
			select {
			case <-ctx.Done():
				cancelled = true
			case gapCh <- queue[idx]:
				idx++
				remain--
				sent = true
			default:
			}
			if !sent && !cancelled && remain > 0 {
				sleep(ctx, time.Second)
			}
		}
	}
	if ctx.Err() != nil {
		cancelled = true
	}
	return
}

func (cdb *PgDB) selectStreamGaps(ctx context.Context, wg *sync.WaitGroup, ls *LogStream, endIndex int64, pageSize int, totals *gapTotals) {
	defer wg.Done()

	if ls != nil {
		gapCh := ls.getGapCh()
		if gapCh != nil {
			if endIndex >= 0 && pageSize > 0 {
				var queue []gap
				var err error
				var lastIndex int64 = -1
				var cancelled bool
				for err == nil && !cancelled && lastIndex < endIndex {
					row := cdb.QueryRow(ctx, cdb.stmtSelectAllGaps, ls.Id, lastIndex, endIndex, pageSize)
					var gapStart sql.NullInt64
					var gapEnd sql.NullInt64
					var lastLogIndex sql.NullInt64
					if err = row.Scan(&gapStart, &gapEnd, &lastLogIndex); err == nil {
						advanced := false
						if gapStart.Valid && gapEnd.Valid {
							g := gap{start: gapStart.Int64, end: gapEnd.Int64}
							if totals != nil {
								totals.add(g)
							}
							if cdb.enqueueGap(ctx, gapCh, &queue, g) {
								cancelled = true
							}
							lastIndex = gapEnd.Int64
							advanced = true
						}
						if !advanced && lastLogIndex.Valid {
							if lastLogIndex.Int64 > lastIndex {
								lastIndex = lastLogIndex.Int64
								advanced = true
							}
						}
						if !advanced {
							break
						}
					}
					if ctx.Err() != nil {
						cancelled = true
					}
				}
				if err == nil && !cancelled {
					if cdb.flushGapQueue(ctx, gapCh, queue) {
						cancelled = true
					}
				}
				if err != nil && !cancelled {
					_ = cdb.LogError(err, "selectAllGaps.stream", "stream", ls.Id, "url", ls.URL())
				}
			}
		}
	}
}

func (cdb *PgDB) selectAllGaps(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	streams := make(map[int32]*LogStream)
	streamIDs := make([]int32, 0, 64)

	cdb.mu.Lock()
	for _, logop := range cdb.operators {
		logop.mu.Lock()
		for _, ls := range logop.streams {
			if ls.gapCh == nil {
				ls.gapCh = make(chan gap, 10)
			}
			streams[ls.Id] = ls
			streamIDs = append(streamIDs, ls.Id)
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
	var endIndexes map[int32]int64
	var err error
	if len(streamIDs) > 0 {
		endIndexes, err = cdb.selectGapEndIndexes(ctx, streamIDs)
	} else {
		endIndexes = map[int32]int64{}
	}

	if err != nil {
		_ = cdb.LogError(err, "selectAllGaps.EndIndexes")
	}

	if err == nil && ctx.Err() == nil {
		pageSize := DbBatchSize
		if pageSize < 100 {
			pageSize = 100
		}
		if pageSize > 10000 {
			pageSize = 10000
		}

		var streamWG sync.WaitGroup
		for streamID, ls := range streams {
			if endIndex, ok := endIndexes[streamID]; ok {
				streamWG.Add(1)
				go cdb.selectStreamGaps(ctx, &streamWG, ls, endIndex, pageSize, &totals)
			}
		}
		streamWG.Wait()
	}

	if ctx.Err() == nil {
		totalgaps, totalgapsize := totals.values()
		cdb.LogInfo("selectAllGaps completed", "totalgapsize", totalgapsize, "totalgaps", totalgaps, "elapsed", time.Since(start).Round(time.Second))
	}
}
