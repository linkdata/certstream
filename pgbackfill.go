package certstream

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
)

var ErrLogEntriesTooOld = errors.New("log entries are older than max age")

type errLogEntriesTooOld struct {
	MaxAge int
}

type rawEntriesFetcher func(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool)

func (e errLogEntriesTooOld) Error() string {
	return "log entries are older than " + strconv.Itoa(e.MaxAge) + " days"
}

func (e errLogEntriesTooOld) Unwrap() error {
	return ErrLogEntriesTooOld
}

func (cdb *PgDB) backfillGapsWithFetcher(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher) {
	if cdb != nil && ls != nil {
		var lastgap gap
		var nullableMaxIndex sql.NullInt64
		lastindex := ls.LastIndex.Load()
		row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
		if err := row.Scan(&nullableMaxIndex); cdb.LogError(err, "backfillGapsWithFetcher/MaxIndex", "url", ls.URL()) == nil {
			if nullableMaxIndex.Valid {
				ls.seeIndex(nullableMaxIndex.Int64)
				if lastindex < nullableMaxIndex.Int64 {
					lastindex = nullableMaxIndex.Int64
				}
				if nullableMaxIndex.Int64 < lastindex {
					lastgap = gap{start: nullableMaxIndex.Int64 + 1, end: lastindex}
				}
			}
		}
		if gapCh := ls.getGapCh(); gapCh != nil {
			fillGap := func(g gap) {
				if ctx.Err() == nil {
					ls.Backfill.Add((g.end - g.start) + 1)
					cdb.LogInfo("gap", "url", ls.URL(), "stream", ls.Id, "logindex", g.start, "length", (g.end-g.start)+1)
					next, _ := fetchFn(ctx, g.start, g.end, true, ls.sendEntry, &ls.Backfill)
					_ = cdb.backfillSetGapStartIndex(ctx, ls, next)
				}
			}
			for gap := range gapCh {
				fillGap(gap)
			}
			if ctx.Err() == nil {
				if lastgap.end != 0 {
					fillGap(lastgap)
				}
				if ctx.Err() == nil && lastindex > 0 {
					_ = cdb.backfillSetGapStartIndex(ctx, ls, lastindex)
				}
			}
		}
	}
}

// return MIN(logindex) for the stream
func (cdb *PgDB) backfillMinIndex(ctx context.Context, ls *LogStream) (minIndex int64, err error) {
	var minIndexRow sql.NullInt64
	row := cdb.QueryRow(ctx, cdb.stmtSelectMinIdx, ls.Id)
	if err = cdb.LogError(row.Scan(&minIndexRow), "Backfill/MinIndex", "url", ls.URL()); err == nil {
		if minIndexRow.Valid {
			minIndex = minIndexRow.Int64
			ls.seeIndex(minIndex)
		}
	}
	return
}

func (cdb *PgDB) backfillGetGapStartIndex(ctx context.Context, ls *LogStream) (gapStartIndex int64, err error) {
	gapStartIndex = -1
	if cdb != nil && ls != nil {
		var storedIndex int64
		row := cdb.QueryRow(ctx, cdb.stmtSelectBackfillIdx, ls.Id)
		if err = cdb.LogError(row.Scan(&storedIndex), "Backfill/StoredIndex", "url", ls.URL()); err == nil {
			if storedIndex > 0 {
				gapStartIndex = storedIndex
			} else {
				gapStartIndex, err = cdb.backfillMinIndex(ctx, ls)
			}
			if err == nil {
				if lastIndex := ls.LastIndex.Load(); lastIndex >= 0 && gapStartIndex > lastIndex {
					gapStartIndex = lastIndex
				}
			}
		}
	}
	return
}

func (cdb *PgDB) backfillSetGapStartIndex(ctx context.Context, ls *LogStream, logindex int64) (err error) {
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
	var err error

	cdb.backfillGapsWithFetcher(ctx, ls, ls.getEntries)
	if minIndex, err = cdb.backfillMinIndex(ctx, ls); err == nil && minIndex > 0 {
		cdb.LogInfo("backlog start", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
		ls.Backfill.Add(minIndex - 1)
		for minIndex > 0 {
			start := max(0, minIndex-LogBatchSize)
			stop := minIndex - 1
			minIndex = start
			var wanted bool
			if _, wanted = ls.getEntries(ctx, start, stop, true, ls.sendEntry, &ls.Backfill); !wanted {
				ls.addError(ls, errLogEntriesTooOld{MaxAge: cdb.PgMaxAge})
				ls.Backfill.Store(0)
				break
			}
		}
		if ctx.Err() == nil {
			cdb.LogInfo("backlog stops", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
		}
	}
}
