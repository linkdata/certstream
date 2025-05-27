package certstream

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var BulkRange = int64(4096)

func (cdb *PgDB) backfillSince(ctx context.Context, wg *sync.WaitGroup) {
	var certid int64
	getquery := cdb.Pfx(`SELECT cert FROM CERTDB_sincequeue LIMIT 1;`)
	delquery := cdb.Pfx(`DELETE FROM CERTDB_sincequeue WHERE cert=$1;`)
	putquery := cdb.Pfx(`INSERT INTO CERTDB_sincequeue (cert) VALUES ($1) ON CONFLICT DO NOTHING;`)
	infoquery := cdb.Pfx(`SELECT commonname,subject,issuer,notbefore FROM CERTDB_cert WHERE id=$1;`)
	updatequery := cdb.Pfx(`UPDATE CERTDB_cert SET since=$1 WHERE commonname=$2 AND subject=$3 AND issuer=$4 AND notbefore <= $5 AND notbefore >= $1;`)
	sleeptime := time.Second

	defer func() {
		if certid != 0 {
			_, _ = cdb.Exec(context.Background(), putquery, certid)
		}
		wg.Done()
	}()

	for ctx.Err() == nil {
		row := cdb.QueryRow(ctx, getquery)
		if err := row.Scan(&certid); err == nil {
			sleeptime = time.Second
			var ct pgconn.CommandTag
			if ct, err = cdb.Exec(ctx, delquery, certid); err == nil {
				if ct.RowsAffected() == 1 {
					row = cdb.QueryRow(ctx, infoquery, certid)
					var commonname string
					var subject, issuer int
					var notbefore time.Time
					if err = row.Scan(&commonname, &subject, &issuer, &notbefore); err == nil {
						row = cdb.QueryRow(ctx, cdb.funcFindSince, commonname, subject, issuer, notbefore)
						var since time.Time
						if err = row.Scan(&since); err == nil && !since.IsZero() {
							if _, err = cdb.Exec(ctx, updatequery, since, commonname, subject, issuer, notbefore); err == nil {
								certid = 0
								continue
							}
						}
					}
					_, _ = cdb.Exec(context.Background(), putquery, certid)
				}
			}
			cdb.LogError(err, "backfillSince", "cert", certid)
		} else {
			sleeptime = min(time.Minute, sleeptime*2)
			select {
			case <-ctx.Done():
				return
			case <-time.NewTimer(sleeptime).C:
			}
		}
	}
}

func (cdb *PgDB) backfillGaps(ctx context.Context, ls *LogStream) {
	type gap struct {
		start int64
		end   int64
	}
	var gaps []gap
	if lastindex := ls.LastIndex.Load(); lastindex != -1 {
		row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
		var nullableMaxIndex sql.NullInt64
		if err := row.Scan(&nullableMaxIndex); cdb.LogError(err, "backfillGaps/MaxIndex", "url", ls.URL) == nil {
			if nullableMaxIndex.Valid {
				ls.seeIndex(nullableMaxIndex.Int64)
				if nullableMaxIndex.Int64 < lastindex {
					gaps = append(gaps, gap{start: nullableMaxIndex.Int64 + 1, end: lastindex})
				}
			}
		}
	}
	if rows, err := cdb.Query(ctx, cdb.stmtSelectGaps, ls.Id); cdb.LogError(err, "backfillGaps/Query", "url", ls.URL) == nil {
		defer rows.Close()
		for rows.Next() {
			var gap_start, gap_end int64
			if err = rows.Scan(&gap_start, &gap_end); cdb.LogError(err, "backfillGaps/Scan", "url", ls.URL) == nil {
				gaps = append(gaps, gap{start: gap_start, end: gap_end})
			}
		}
		rows.Close()
	}
	for _, gap := range gaps {
		ls.InsideGaps.Add((gap.end - gap.start) + 1)
	}
	for _, gap := range gaps {
		if ctx.Err() == nil {
			cdb.LogInfo("gap", "url", ls.URL, "stream", ls.Id, "logindex", gap.start, "length", (gap.end-gap.start)+1)
			ls.GetRawEntries(ctx, gap.start, gap.end, true, ls.sendEntry, &ls.InsideGaps)
		}
	}
}

func (cdb *PgDB) backfillStream(ctx context.Context, ls *LogStream, wg *sync.WaitGroup) {
	defer wg.Done()
	wg.Add(1)
	go cdb.backfillSince(ctx, wg)
	row := cdb.QueryRow(ctx, cdb.stmtSelectMinIdx, ls.Id)
	var nullableMinIndex sql.NullInt64
	if err := cdb.LogError(row.Scan(&nullableMinIndex), "Backfill/MinIndex", "url", ls.URL); err == nil {
		if !nullableMinIndex.Valid {
			nullableMinIndex.Int64 = ls.LastIndex.Load()
		}
		minIndex := nullableMinIndex.Int64
		ls.seeIndex(minIndex)
		cdb.backfillGaps(ctx, ls)
		if minIndex > 0 && ctx.Err() == nil {
			cdb.LogInfo("backlog start", "url", ls.URL, "stream", ls.Id, "logindex", minIndex)
			for minIndex > 0 && ctx.Err() == nil {
				start := max(0, minIndex-BulkRange)
				stop := minIndex - 1
				minIndex = start
				if !ls.GetRawEntries(ctx, start, stop, true, ls.sendEntry, nil) {
					cdb.LogInfo("backlog stops", "url", ls.URL, "stream", ls.Id, "logindex", minIndex)
					ls.addError(ls, fmt.Errorf("log entries are older than %d days", cdb.PgMaxAge))
					return
				}
			}
		}
	}
}
