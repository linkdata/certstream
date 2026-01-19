package certstream

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync"
)

var BulkRange = int64(4096)
var ErrLogEntriesTooOld = errors.New("log entries are older than max age")

type errLogEntriesTooOld struct {
	MaxAge int
}

func (e errLogEntriesTooOld) Error() string {
	return "log entries are older than " + strconv.Itoa(e.MaxAge) + " days"
}

func (e errLogEntriesTooOld) Unwrap() error {
	return ErrLogEntriesTooOld
}

func (cdb *PgDB) backfillGaps(ctx context.Context, ls *LogStream) {
	var lastgap gap
	if lastindex := ls.LastIndex.Load(); lastindex != -1 {
		row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
		var nullableMaxIndex sql.NullInt64
		if err := row.Scan(&nullableMaxIndex); cdb.LogError(err, "backfillGaps/MaxIndex", "url", ls.URL()) == nil {
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
				cdb.LogInfo("gap", "url", ls.URL(), "stream", ls.Id, "logindex", gap.start, "length", (gap.end-gap.start)+1)
				ls.getRawEntries(ctx, gap.start, gap.end, true, ls.sendEntry, &ls.InsideGaps)
			}
		}
		if lastgap.end != 0 && ctx.Err() == nil {
			ls.InsideGaps.Add((lastgap.end - lastgap.start) + 1)
			cdb.LogInfo("last gap", "url", ls.URL(), "stream", ls.Id, "logindex", lastgap.start, "length", (lastgap.end-lastgap.start)+1)
			ls.getRawEntries(ctx, lastgap.start, lastgap.end, true, ls.sendEntry, &ls.InsideGaps)
		}
	}
}

func (cdb *PgDB) backfillStartIndex(ctx context.Context, ls *LogStream) (minIndex int64, stored bool, err error) {
	minIndex = -1
	if cdb != nil && ls != nil {
		var storedIndex int64
		row := cdb.QueryRow(ctx, cdb.stmtSelectBackfillIdx, ls.Id)
		if err = cdb.LogError(row.Scan(&storedIndex), "Backfill/StoredIndex", "url", ls.URL()); err == nil {
			if storedIndex > 0 {
				minIndex = storedIndex
				stored = true
			} else {
				var minIndexRow sql.NullInt64
				row = cdb.QueryRow(ctx, cdb.stmtSelectMinIdx, ls.Id)
				if err = cdb.LogError(row.Scan(&minIndexRow), "Backfill/MinIndex", "url", ls.URL()); err == nil {
					if minIndexRow.Valid {
						minIndex = minIndexRow.Int64
					} else {
						minIndex = ls.LastIndex.Load()
					}
				}
			}
			if err == nil {
				if lastIndex := ls.LastIndex.Load(); lastIndex >= 0 && minIndex > lastIndex {
					minIndex = lastIndex
				}
			}
		}
	}
	return
}

func (cdb *PgDB) updateBackfillIndex(ctx context.Context, ls *LogStream, logindex int64) (err error) {
	if cdb != nil && ls != nil {
		if ctx.Err() == nil {
			if logindex >= 0 {
				_, err = cdb.Exec(ctx, cdb.stmtUpdateBackfillIdx, logindex, ls.Id)
				err = cdb.LogError(err, "Backfill/UpdateIndex", "url", ls.URL(), "stream", ls.Id, "logindex", logindex)
			}
		}
	}
	return
}

func (cdb *PgDB) backfillStream(ctx context.Context, ls *LogStream, wg *sync.WaitGroup) {
	defer wg.Done()
	var minIndex int64
	var stored bool
	var err error
	if minIndex, stored, err = cdb.backfillStartIndex(ctx, ls); err == nil {
		if !stored {
			_ = cdb.updateBackfillIndex(ctx, ls, minIndex)
		}
		ls.seeIndex(minIndex)
		cdb.backfillGaps(ctx, ls)
		if minIndex > 0 && ctx.Err() == nil {
			cdb.LogInfo("backlog start", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
			stopBackfill := false
			for minIndex > 0 && ctx.Err() == nil && !stopBackfill {
				start := max(0, minIndex-BulkRange)
				stop := minIndex - 1
				minIndex = start
				if !ls.getRawEntries(ctx, start, stop, true, ls.sendEntry, nil) {
					cdb.LogInfo("backlog stops", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
					ls.addError(ls, errLogEntriesTooOld{MaxAge: cdb.PgMaxAge})
					stopBackfill = true
				}
				if ctx.Err() == nil {
					_ = cdb.updateBackfillIndex(ctx, ls, minIndex)
				}
			}
		}
	}
}
