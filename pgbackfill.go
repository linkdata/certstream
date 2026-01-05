package certstream

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

var BulkRange = int64(4096)

func (cdb *PgDB) backfillGaps(ctx context.Context, ls *LogStream) {
	var lastgap gap
	if lastindex := ls.LastIndex.Load(); lastindex != -1 {
		row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
		var nullableMaxIndex sql.NullInt64
		if err := row.Scan(&nullableMaxIndex); cdb.LogError(err, "backfillGaps/MaxIndex", "url", ls.URL) == nil {
			if nullableMaxIndex.Valid {
				ls.seeIndex(nullableMaxIndex.Int64)
				if nullableMaxIndex.Int64 < lastindex {
					lastgap = gap{start: nullableMaxIndex.Int64 + 1, end: lastindex}
				}
			}
		}
	}
	if gapCh := ls.getGapCh(); gapCh != nil {
		for gap := range gapCh {
			if ctx.Err() == nil {
				ls.InsideGaps.Add((gap.end - gap.start) + 1)
				cdb.LogInfo("gap", "url", ls.URL, "stream", ls.Id, "logindex", gap.start, "length", (gap.end-gap.start)+1)
				ls.getRawEntries(ctx, gap.start, gap.end, true, ls.sendEntry, &ls.InsideGaps)
			}
		}
		if lastgap.end != 0 && ctx.Err() == nil {
			cdb.LogInfo("last gap", "url", ls.URL, "stream", ls.Id, "logindex", lastgap.start, "length", (lastgap.end-lastgap.start)+1)
			ls.getRawEntries(ctx, lastgap.start, lastgap.end, true, ls.sendEntry, &ls.InsideGaps)
		}
	}
}

func (cdb *PgDB) backfillStream(ctx context.Context, ls *LogStream, wg *sync.WaitGroup) {
	defer wg.Done()
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
				if !ls.getRawEntries(ctx, start, stop, true, ls.sendEntry, nil) {
					cdb.LogInfo("backlog stops", "url", ls.URL, "stream", ls.Id, "logindex", minIndex)
					ls.addError(ls, fmt.Errorf("log entries are older than %d days", cdb.PgMaxAge))
					return
				}
			}
		}
	}
}
