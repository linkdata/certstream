package certstream

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

var BulkRange = int64(4096)

func (cdb *PgDB) backfillGaps(ctx context.Context, ls *LogStream) {
	type gap struct {
		start int64
		end   int64
	}
	var gaps []gap
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
	if lastindex := ls.LastIndex.Load(); lastindex != -1 {
		row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
		var nullableMaxIndex sql.NullInt64
		if err := row.Scan(&nullableMaxIndex); cdb.LogError(err, "backfillGaps/MaxIndex", "url", ls.URL) == nil {
			if nullableMaxIndex.Valid && nullableMaxIndex.Int64 < lastindex {
				gaps = append(gaps, gap{start: nullableMaxIndex.Int64 + 1, end: lastindex})
			}
		}
	}
	for _, gap := range gaps {
		ls.InsideGaps.Add((gap.end - gap.start) + 1)
	}
	for _, gap := range gaps {
		if ctx.Err() == nil {
			cdb.LogInfo("gap", "url", ls.URL, "stream", ls.Id, "logindex", gap.start, "length", (gap.end-gap.start)+1)
			ls.GetRawEntries(ctx, gap.start, gap.end, true, &ls.InsideGaps)
		}
	}
}

func (cdb *PgDB) backfillStream(ctx context.Context, ls *LogStream, wg *sync.WaitGroup) {
	defer wg.Done()
	cdb.backfillGaps(ctx, ls)
	row := cdb.QueryRow(ctx, cdb.stmtSelectMinIdx, ls.Id)
	var nullableMinIndex sql.NullInt64
	if err := cdb.LogError(row.Scan(&nullableMinIndex), "Backfill/MinIndex", "url", ls.URL); err == nil {
		if !nullableMinIndex.Valid {
			nullableMinIndex.Int64 = ls.LastIndex.Load()
		}
		minIndex := nullableMinIndex.Int64
		if minIndex > 0 {
			cdb.LogInfo("backlog start", "url", ls.URL, "stream", ls.Id, "logindex", minIndex)
			for minIndex > 0 && ctx.Err() == nil {
				start := max(0, minIndex-BulkRange)
				stop := minIndex - 1
				minIndex = start
				if youngest := ls.GetRawEntries(ctx, start, stop, true, nil); youngest > time.Hour*24*time.Duration(cdb.PgMaxAge) {
					cdb.LogInfo("backlog stop", "url", ls.URL, "stream", ls.Id, "logindex", minIndex, "age", youngest)
					return
				}
			}
		}
	}
}
