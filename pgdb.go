package certstream

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
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
	funcEnsureIdent       string
	funcFindSince         string
	funcIngestBatch       string
	stmtEnsureCert        string
	stmtAttachMetadata    string
	stmtSelectGaps        string
	stmtSelectAllGaps     string
	stmtSelectMinIdx      string
	stmtSelectMaxIdx      string
	stmtSelectDnsnameLike string
	stmtSelectIDSince     string
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
		if _, err = db.Exec(ctx, pfx(FuncDeleteDomainDuplicates)); err == nil {
			if _, err = db.Exec(ctx, pfx(FunctionOperatorID)); err == nil {
				if _, err = db.Exec(ctx, pfx(FunctionStreamID)); err == nil {
					if _, err = db.Exec(ctx, pfx(FunctionFindSince)); err == nil {
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
	const callFindSince = `SELECT CERTDB_find_since($1,$2,$3,$4);`
	const callEnsureCert = `SELECT CERTDB_ensure_cert($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);`
	const callAttachMetadata = `SELECT CERTDB_attach_metadata($1,$2,$3,$4,$5);`

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
							funcEnsureIdent:       pfx(`SELECT CERTDB_ensure_ident($1,$2,$3);`),
							funcFindSince:         pfx(callFindSince),
							funcIngestBatch:       pfx(`SELECT CERTDB_ingest_batch($1::jsonb);`),
							stmtEnsureCert:        pfx(callEnsureCert),
							stmtAttachMetadata:    pfx(callAttachMetadata),
							stmtSelectGaps:        pfx(SelectGaps),
							stmtSelectAllGaps:     pfx(SelectAllGaps),
							stmtSelectMinIdx:      pfx(SelectMinIndex),
							stmtSelectMaxIdx:      pfx(SelectMaxIndex),
							stmtSelectDnsnameLike: pfx(SelectDnsnameLike),
							stmtSelectIDSince:     pfx(SelectIDSince),
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
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_ident WHERE id=$1;`), id)
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

func (cdb *PgDB) GetCertificateSince(ctx context.Context, jcert *JsonCertificate) (since time.Time, err error) {
	if jcert.CommonName != "" {
		ctx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		row := cdb.QueryRow(ctx, cdb.stmtSelectIDSince,
			jcert.CommonName,
			jcert.Subject.Organization, jcert.Subject.Province, jcert.Subject.Country,
			jcert.Issuer.Organization, jcert.Issuer.Province, jcert.Issuer.Country,
			jcert.NotBefore,
		)
		var id int64
		var subject, issuer int
		var notbefore time.Time
		var p_since *time.Time
		if err = row.Scan(&id, &subject, &issuer, &notbefore, &p_since); err == nil {
			if p_since != nil {
				since = *p_since
			} else {
				since = notbefore
			}
		}
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			_ = cdb.LogError(err, "GetCertificateSince", "signature", jcert.Signature, "query", strings.ReplaceAll(RenderSQL(cdb.stmtSelectIDSince,
				jcert.CommonName,
				jcert.Subject.Organization, jcert.Subject.Province, jcert.Subject.Country,
				jcert.Issuer.Organization, jcert.Issuer.Province, jcert.Issuer.Country,
				jcert.NotBefore), "\n", " "))
		}
	}
	return
}

func (cdb *PgDB) GetCertificatesByCommonName(ctx context.Context, commonname string) (certs []*JsonCertificate, err error) {
	var rows pgx.Rows
	if rows, err = cdb.Query(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE commonname=$1 ORDER BY notbefore DESC;`), commonname); err == nil {
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
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE sha256=$1;`), hash)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
	}
	return
}

func (cdb *PgDB) GetCertificateByID(ctx context.Context, id int64) (cert *JsonCertificate, err error) {
	row := cdb.QueryRow(ctx, cdb.Pfx(`SELECT * FROM CERTDB_cert WHERE id=$1;`), id)
	var dbcert PgCertificate
	if err = ScanCertificate(row, &dbcert); err == nil {
		cert, err = cdb.getCertificate(ctx, &dbcert)
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

func (cdb *PgDB) selectAllGaps(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	type queued struct {
		streamID int32
		gap      gap
	}
	var queue []queued
	var streamIds []byte
	streams := make(map[int32]*LogStream)

	cdb.mu.Lock()
	for _, logop := range cdb.operators {
		logop.mu.Lock()
		for _, ls := range logop.streams {
			ls.gapCh = make(chan gap, 10)
			streams[ls.Id] = ls
			if len(streamIds) > 0 {
				streamIds = append(streamIds, ',')
			}
			streamIds = strconv.AppendInt(streamIds, int64(ls.Id), 10)
		}
		logop.mu.Unlock()
	}
	cdb.mu.Unlock()

	defer func() {
		for _, ls := range streams {
			ls.mu.Lock()
			close(ls.gapCh)
			ls.gapCh = nil
			ls.mu.Unlock()
		}
	}()

	start := time.Now()
	cdb.LogInfo("selectAllGaps starts", "streams", len(streams))
	var totalgaps, totalgapsize int64

	tx, err := cdb.BeginTx(ctx, pgx.TxOptions{})
	var query string
	if cdb.LogError(err, "selectAllGaps.BeginTX") == nil {
		defer tx.Commit(ctx)
		cursorName := fmt.Sprintf("certstreamgaps%x", rand.Int64() /*#nosec G404*/)
		query = cdb.Pfx(fmt.Sprintf(`DECLARE %s CURSOR FOR `+cdb.stmtSelectAllGaps, cursorName, string(streamIds)))
		if _, err = tx.Exec(ctx, query); cdb.LogError(err, "selectAllGaps.DECLARE") == nil {
			query = fmt.Sprintf(`FETCH 1 IN %s;`, cursorName)
			for err == nil {
				var rows pgx.Rows
				if rows, err = tx.Query(ctx, query); cdb.LogError(err, "selectAllGaps.Query") == nil {
					for rows.Next() {
						var streamID int32
						var gap_start, gap_end int64
						if cdb.LogError(rows.Scan(&streamID, &gap_start, &gap_end), "selectAllGaps.Scan") == nil {
							totalgaps++
							totalgapsize += (gap_end - gap_start) + 1
							q := queued{streamID: streamID, gap: gap{start: gap_start, end: gap_end}}
							if ls := streams[streamID]; ls != nil {
								gapCh := ls.getGapCh()
								select {
								case <-ctx.Done():
									rows.Close()
									return
								case gapCh <- q.gap:
								default:
									queue = append(queue, q)
								}
							}
						}
					}
					err = cdb.LogError(rows.Err(), "selectAllGaps.rows.Err")
					if rows.CommandTag().RowsAffected() == 0 {
						break
					}
				}
			}
		}
		_ = tx.Commit(ctx)

		remain := len(queue)
		if remain > 0 {
			cdb.LogInfo("selectAllGaps waiting", "totalgapsize", totalgapsize, "totalgaps", totalgaps, "remain", remain, "elapsed", time.Since(start).Round(time.Second))
			for remain > 0 {
				for i := range queue {
					if queue[i].gap.start != -1 {
						if ls := streams[queue[i].streamID]; ls != nil {
							select {
							case <-ctx.Done():
								return
							case ls.gapCh <- queue[i].gap:
								remain--
								queue[i].gap.start = -1
							default:
							}
						}
					}
				}
				sleep(ctx, time.Second)
			}
		}
		cdb.LogInfo("selectAllGaps completed", "totalgapsize", totalgapsize, "totalgaps", totalgaps, "elapsed", time.Since(start).Round(time.Second))
	}
}
