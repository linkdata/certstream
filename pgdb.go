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
	stmtFindGap           string
	stmtSelectMinIdx      string
	stmtSelectMaxIdx      string
	stmtSelectMinIdxFrom  string
	stmtSelectBackfillIdx string
	stmtUpdateBackfillIdx string
	closeMu               sync.RWMutex   // blocks new tracked calls while Close is waiting
	closeWG               sync.WaitGroup // tracks exported DB operations
	closeOnce             sync.Once
	mu                    sync.Mutex // protects following
	batchCh               []chan *LogEntry
	workerBits            int
	workerCount           int
	estimates             map[string]float64 // row count estimates
	cleanFrom             time.Time          // lowest notafter DeleteCertificates has yet to consider
	cleanResetAt          time.Time          // when cleanFrom was last restarted
	cleanStream           map[int32]int64    // per stream, lowest logindex DeleteStream has yet to consider
	newentrytime          time.Duration
	newentrycount         int64
	avgentrytime          time.Duration
}

func ensureSchema(ctx context.Context, db *pgxpool.Pool, pfx func(string) string) (err error) {
	if _, err = db.Exec(ctx, pfx(CreateSchema)); err == nil {
		if _, err = db.Exec(ctx, pfx(FunctionOperatorID)); err == nil {
			if _, err = db.Exec(ctx, pfx(FunctionStreamID)); err == nil {
				if _, err = db.Exec(ctx, pfx(FuncSetSince)); err == nil {
					if _, err = db.Exec(ctx, pfx(FuncSubdomain)); err == nil {
						_, err = db.Exec(ctx, pfx(FuncIngestBatch))
					}
				}
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
		if !cs.Config.PgSyncCommit {
			dsn += "&synchronous_commit=off"
		}
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
							batchChans[i] = make(chan *LogEntry, DbIngestBatchSize*2)
						}
						cdb = &PgDB{
							CertStream:            cs,
							Pool:                  pool,
							Pfx:                   pfx,
							funcOperatorID:        pfx(callOperatorID),
							funcStreamID:          pfx(callStreamID),
							funcIngestBatch:       pfx(`SELECT CERTDB_ingest_batch($1::jsonb);`),
							stmtFindGap:           pfx(SelectFindGap),
							stmtSelectMinIdx:      pfx(SelectMinIndex),
							stmtSelectMaxIdx:      pfx(SelectMaxIndex),
							stmtSelectMinIdxFrom:  pfx(SelectMinIndexFrom),
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

func (cdb *PgDB) beginCall() {
	if cdb != nil {
		cdb.closeMu.RLock()
		cdb.closeWG.Add(1)
		cdb.closeMu.RUnlock()
	}
}

func (cdb *PgDB) endCall() {
	if cdb != nil {
		cdb.closeWG.Done()
	}
}

func (cdb *PgDB) Close() {
	if cdb != nil {
		cdb.closeOnce.Do(func() {
			cdb.closeMu.Lock()
			cdb.mu.Lock()
			chans := cdb.batchCh
			cdb.batchCh = nil
			cdb.mu.Unlock()
			for _, ch := range chans {
				if ch != nil {
					close(ch)
				}
			}
			cdb.closeWG.Wait()
			cdb.Pool.Close()
			cdb.closeMu.Unlock()
		})
	}
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
	cert, err = cdb.getCertificateByID(ctx, entry.CertID)
	return
}

func (cdb *PgDB) getCertificateByID(ctx context.Context, id int64) (cert *JsonCertificate, err error) {
	if cdb != nil {
		cdb.beginCall()
		defer cdb.endCall()
		row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT id, notbefore, notafter, commonname, subject, issuer, sha256, precert, since FROM CERTDB_cert WHERE id=$1;`), id)
		var dbcert PgCertificate
		if err = ScanCertificate(row, &dbcert); err == nil {
			cert, err = cdb.getCertificate(ctx, &dbcert)
		}
	}
	return
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
	if cdb != nil {
		cdb.beginCall()
		defer cdb.endCall()
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
	}
	return
}

func (cdb *PgDB) GetCertificateByHash(ctx context.Context, hash []byte) (cert *JsonCertificate, err error) {
	if cdb != nil {
		cdb.beginCall()
		defer cdb.endCall()
		row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT id, notbefore, notafter, commonname, subject, issuer, sha256, precert, since FROM CERTDB_cert WHERE sha256=$1;`), hash)
		var dbcert PgCertificate
		if err = ScanCertificate(row, &dbcert); err == nil {
			cert, err = cdb.getCertificate(ctx, &dbcert)
		}
	}
	return
}

func (cdb *PgDB) GetCertificateByID(ctx context.Context, id int64) (cert *JsonCertificate, err error) {
	cert, err = cdb.getCertificateByID(ctx, id)
	return
}

func (cdb *PgDB) GetHistoricalCertificates(ctx context.Context, expiresAfter time.Time, callback func(ctx context.Context, cert *JsonCertificate) (err error)) (err error) {
	if cdb != nil {
		cdb.beginCall()
		defer cdb.endCall()
		expiresAfter = expiresAfter.UTC()
		var maxNotAfter *time.Time
		if err = cdb.QueryRow(ctx, cdb.Pfx(`SELECT MAX(notafter) FROM CERTDB_cert;`)).Scan(&maxNotAfter); err == nil {
			if maxNotAfter != nil {
				maxAtStart := maxNotAfter.UTC()
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
					if rows, err = cdb.Query(ctx, query, expiresAfter, maxAtStart, lastNotAfter, lastID, max(100, HistoricalBatchSize)); err == nil {
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

// CleanBatchSize is the number of certificates the automatic cleanup deletes per statement.
var CleanBatchSize = 10000

// CleanResetInterval is how often [PgDB.DeleteCertificates] restarts at the
// oldest certificate instead of resuming from its cursor.
var CleanResetInterval = time.Hour

// DeleteCertificates deletes up to batchSize certificates that expired at or
// before cutoff, oldest first, cascading to the domain, IP address, email and
// URI rows that reference them. Rows in CERTDB_entry are left alone: they
// record log positions and have no foreign key to CERTDB_cert.
//
// Deletion resumes where the previous call stopped, so repeated calls walk
// forward in notafter order instead of rescanning the index entries of rows
// already deleted. Finding nothing to delete moves the cursor up to cutoff,
// and at most once every [CleanResetInterval] restarts it at the oldest
// certificate to pick up any inserted below it.
//
// A batchSize below one deletes nothing.
func (cdb *PgDB) DeleteCertificates(ctx context.Context, cutoff time.Time, batchSize int) (rowsDeleted int64, err error) {
	if cdb != nil {
		cdb.beginCall()
		defer cdb.endCall()
		if batchSize > 0 {
			cutoff = cutoff.UTC()
			query := cdb.Pfx(`WITH CERTDB_clean_cert AS (
  SELECT ctid
  FROM CERTDB_cert
  WHERE notafter >= $1 AND notafter <= $2
  ORDER BY notafter ASC
  LIMIT $3
  FOR UPDATE SKIP LOCKED
), CERTDB_deleted_cert AS (
  DELETE FROM CERTDB_cert
  USING CERTDB_clean_cert
  WHERE CERTDB_cert.ctid = CERTDB_clean_cert.ctid
  RETURNING CERTDB_cert.notafter
)
SELECT count(*), max(notafter) FROM CERTDB_deleted_cert;`)
			cdb.mu.Lock()
			cleanFrom := cdb.cleanFrom
			cdb.mu.Unlock()
			var highest sql.NullTime
			row := cdb.QueryRow(ctx, query, cleanFrom, cutoff, batchSize)
			if err = row.Scan(&rowsDeleted, &highest); err == nil {
				now := time.Now()
				cdb.mu.Lock()
				switch {
				case highest.Valid && highest.Time.After(cdb.cleanFrom):
					cdb.cleanFrom = highest.Time
				case rowsDeleted > 0:
				case now.Sub(cdb.cleanResetAt) >= CleanResetInterval:
					// Sweep back for certificates inserted below the cursor. The
					// scan that follows has to walk whatever the range still holds,
					// so it happens on an interval rather than every idle cycle.
					cdb.cleanFrom = time.Time{}
					cdb.cleanResetAt = now
				case cutoff.After(cdb.cleanFrom):
					// Nothing left at or above the cursor, so start the next scan at
					// the cutoff instead of walking the emptied range again.
					cdb.cleanFrom = cutoff
				}
				cdb.mu.Unlock()
			}
		}
	}
	return
}

// CleanCertificates deletes expired certificates until ctx is done.
//
// A certificate is deleted once Config.PgCertMaxAge has passed since it
// expired. A PgCertMaxAge of zero or less returns immediately without
// deleting anything. [Start] runs this for the lifetime of the CertStream,
// so callers need it only when driving a [PgDB] themselves.
func (cdb *PgDB) CleanCertificates(ctx context.Context) {
	maxAge := cdb.CertStream.Config.PgCertMaxAge
	if maxAge <= 0 {
		return
	}
	for ctx.Err() == nil {
		rowsDeleted, err := cdb.DeleteCertificates(ctx, time.Now().UTC().Add(-maxAge), CleanBatchSize)
		if cdb.LogError(err, "CleanCertificates") != nil || rowsDeleted == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(time.Minute):
			}
		}
	}
}

// DeleteStream deletes up to batchSize log entries belonging to the stream,
// oldest first, and deletes the stream itself once it holds none.
//
// Deletion resumes where the previous call stopped, so repeated calls walk
// forward in logindex order instead of rescanning the index entries of rows
// already deleted. Reaching the end of the stream restarts the scan at its
// first entry, so entries backfilled below the cursor are still found.
//
// The stream itself is deleted only once it holds no entries at all, checked
// under a lock on the stream row. A batch deleting nothing is not on its own
// proof of that, since rows locked by another deleter are skipped.
//
// A batchSize below one deletes nothing.
func (cdb *PgDB) DeleteStream(ctx context.Context, streamId int32, batchSize int) (rowsDeleted int64, err error) {
	if cdb != nil {
		cdb.beginCall()
		defer cdb.endCall()
		if batchSize > 0 {
			query := cdb.Pfx(`WITH CERTDB_clean_stream AS (
  SELECT ctid
  FROM CERTDB_entry
  WHERE stream = $1 AND logindex >= $2
  ORDER BY logindex ASC
  LIMIT $3
  FOR UPDATE SKIP LOCKED
), CERTDB_deleted_entry AS (
  DELETE FROM CERTDB_entry
  USING CERTDB_clean_stream
  WHERE CERTDB_entry.ctid = CERTDB_clean_stream.ctid
  RETURNING CERTDB_entry.logindex
)
SELECT count(*), max(logindex) FROM CERTDB_deleted_entry;`)
			deleteBatch := func(from int64) (deleted int64, next int64, batchErr error) {
				var highest sql.NullInt64
				if batchErr = cdb.QueryRow(ctx, query, streamId, from, batchSize).Scan(&deleted, &highest); batchErr == nil {
					if highest.Valid {
						next = highest.Int64 + 1
					}
				}
				return
			}
			cdb.mu.Lock()
			from := cdb.cleanStream[streamId]
			cdb.mu.Unlock()
			var next int64
			if rowsDeleted, next, err = deleteBatch(from); err == nil {
				if rowsDeleted == 0 && from != 0 {
					// Nothing above the cursor, so look again from the start in
					// case backfill added entries below it.
					rowsDeleted, next, err = deleteBatch(0)
				}
				if err == nil {
					cdb.mu.Lock()
					// A zero cursor means the same as no cursor at all, so drop
					// the entry rather than keeping one per stream id ever asked
					// about, including ids that do not exist.
					if next == 0 {
						delete(cdb.cleanStream, streamId)
					} else {
						if cdb.cleanStream == nil {
							cdb.cleanStream = make(map[int32]int64)
						}
						cdb.cleanStream[streamId] = next
					}
					cdb.mu.Unlock()
					if rowsDeleted == 0 {
						rowsDeleted, err = cdb.deleteEmptyStream(ctx, streamId)
					}
				}
			}
		}
	}
	return
}

// deleteEmptyStream deletes the stream, and reports how many rows that removed,
// but only once it holds no entries.
//
// The stream row is locked before the check, so that inserting an entry, which
// takes a FOR KEY SHARE lock on that row for the foreign key, cannot commit
// between the check and the delete. Testing inside a single
// DELETE ... WHERE NOT EXISTS is not enough: the subquery sees the statement
// snapshot, so an entry committed after that snapshot is taken is invisible to
// it and still removed by the cascade.
func (cdb *PgDB) deleteEmptyStream(ctx context.Context, streamId int32) (rowsDeleted int64, err error) {
	var tx pgx.Tx
	if tx, err = cdb.Begin(ctx); err == nil {
		defer func() {
			_ = tx.Rollback(ctx)
		}()
		var lockedId int32
		if err = tx.QueryRow(ctx, cdb.Pfx(`SELECT id FROM CERTDB_stream WHERE id = $1 FOR UPDATE;`), streamId).Scan(&lockedId); err == nil {
			var hasEntries bool
			if err = tx.QueryRow(ctx, cdb.Pfx(`SELECT EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1);`), streamId).Scan(&hasEntries); err == nil {
				if !hasEntries {
					var tag pgconn.CommandTag
					if tag, err = tx.Exec(ctx, cdb.Pfx(`DELETE FROM CERTDB_stream WHERE id = $1;`), streamId); err == nil {
						rowsDeleted = tag.RowsAffected()
					}
				}
				if err == nil {
					err = tx.Commit(ctx)
				}
			}
		} else if errors.Is(err, pgx.ErrNoRows) {
			err = nil
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
	ticker := time.NewTicker(time.Minute)
	defer func() {
		wg.Done()
		ticker.Stop()
	}()
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

func (cdb *PgDB) selectStreamGaps(ctx context.Context, wg *sync.WaitGroup, ls *LogStream, totals *gapTotals) {
	defer wg.Done()

	gapCh := ls.getGapCh()
	if gapCh != nil {
		defer func() {
			ls.mu.Lock()
			if ls.gapCh == gapCh {
				close(gapCh)
			}
			ls.mu.Unlock()
		}()
		var err error
		var maxIndex sql.NullInt64
		if err = cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id).Scan(&maxIndex); err == nil {
			endIndex := int64(-1)
			if maxIndex.Valid {
				endIndex = maxIndex.Int64
			}
			if endIndex >= 0 {
				var lastIndex int64
				if err = cdb.QueryRow(ctx, cdb.stmtSelectBackfillIdx, ls.Id).Scan(&lastIndex); err == nil {
					var startIndex sql.NullInt64
					if err = cdb.QueryRow(ctx, cdb.stmtSelectMinIdxFrom, ls.Id, lastIndex).Scan(&startIndex); err == nil {
						if startIndex.Valid {
							hadGaps := false
							if startIndex.Int64 > lastIndex {
								if lastIndex > 0 && ctx.Err() == nil {
									g := gap{start: lastIndex, end: startIndex.Int64 - 1}
									select {
									case <-ctx.Done():
									case gapCh <- g:
										hadGaps = true
										if totals != nil {
											totals.add(g)
										}
									}
								} else if ctx.Err() == nil {
									_ = cdb.backfillSetGapStartIndex(ctx, ls, startIndex.Int64)
								}
								lastIndex = startIndex.Int64
							}
							stmt := cdb.stmtFindGap
							for err == nil && ctx.Err() == nil && lastIndex < endIndex {
								row := cdb.QueryRow(ctx, stmt, ls.Id, lastIndex, endIndex)
								var gapStart sql.NullInt64
								var gapEnd sql.NullInt64
								if err = row.Scan(&gapStart, &gapEnd); err == nil {
									if gapStart.Valid && gapEnd.Valid {
										g := gap{start: gapStart.Int64, end: gapEnd.Int64}
										select {
										case <-ctx.Done():
										case gapCh <- g:
											lastIndex = gapEnd.Int64 + 1
											hadGaps = true
											if totals != nil {
												totals.add(g)
											}
										}
									} else if ctx.Err() == nil {
										if !hadGaps {
											if err = cdb.backfillSetGapStartIndex(ctx, ls, endIndex); err == nil {
												lastIndex = endIndex
											}
										}
										break
									}
								}
							}
						}
					}
				}
			}
		}
		_ = cdb.LogError(err, "selectAllGaps.stream", "stream", ls.Id, "url", ls.URL())
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
				ls.gapCh = make(chan gap, 8)
			}
			streams[ls.Id] = ls
		}
		logop.mu.Unlock()
	}
	cdb.mu.Unlock()

	start := time.Now()
	cdb.LogInfo("selectAllGaps starts", "streams", len(streams))

	var totals gapTotals
	var streamWG sync.WaitGroup
	for _, ls := range streams {
		streamWG.Add(1)
		go cdb.selectStreamGaps(ctx, &streamWG, ls, &totals)
	}
	streamWG.Wait()

	if ctx.Err() == nil {
		totalgaps, totalgapsize := totals.values()
		cdb.LogInfo("selectAllGaps completed", "totalgapsize", totalgapsize, "totalgaps", totalgaps, "elapsed", time.Since(start).Round(time.Second))
	}
}
