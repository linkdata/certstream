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
	var lastgap gap
	if cdb != nil && ls != nil {
		if lastindex := ls.LastIndex.Load(); lastindex != -1 {
			row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
			var nullableMaxIndex sql.NullInt64
			if err := row.Scan(&nullableMaxIndex); cdb.LogError(err, "backfillGapsWithFetcher/MaxIndex", "url", ls.URL()) == nil {
				if nullableMaxIndex.Valid {
					ls.seeIndex(nullableMaxIndex.Int64)
					if nullableMaxIndex.Int64 < lastindex {
						lastgap = gap{start: nullableMaxIndex.Int64 + 1, end: lastindex}
					}
				}
			}
		}
		if gapCh := ls.getGapCh(); gapCh != nil {
			fillGap := func(g gap) {
				if ctx.Err() == nil {
					ls.Backfill.Add((g.end - g.start) + 1)
					cdb.LogInfo("gap", "url", ls.URL(), "stream", ls.Id, "logindex", g.start, "length", (g.end-g.start)+1)
					fetchFn(ctx, g.start, g.end, true, ls.sendEntry, &ls.Backfill)
					if ctx.Err() == nil {
						_ = cdb.updateBackfillIndex(ctx, ls, g.end+1)
					}
				}
			}
			for gap := range gapCh {
				fillGap(gap)
			}
			if lastgap.end != 0 {
				fillGap(lastgap)
			}
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
		cdb.backfillGapsWithFetcher(ctx, ls, ls.getEntries)
		if minIndex > 0 && ctx.Err() == nil {
			cdb.LogInfo("backlog start", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
			ls.Backfill.Add(minIndex - 1)
			for minIndex > 0 {
				start := max(0, minIndex-LogBatchSize)
				stop := minIndex - 1
				minIndex = start
				var wanted bool
				if _, wanted = ls.getEntries(ctx, start, stop, true, ls.sendEntry, &ls.Backfill); !wanted {
					if ctx.Err() == nil {
						ls.addError(ls, errLogEntriesTooOld{MaxAge: cdb.PgMaxAge})
					}
					ls.Backfill.Store(0)
					break
				}
			}
			cdb.LogInfo("backlog stops", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
		}
	}
}
