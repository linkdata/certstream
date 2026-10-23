package certstream

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/sunlight"
)

var (
	// ErrLogEntriesTooOld reports that historical entries exceed the configured maximum age.
	ErrLogEntriesTooOld = errors.New("log entries are older than max age")
	errGapIncomplete    = errors.New("gap fetch incomplete")
)

type errLogEntriesTooOld struct {
	MaxAge int
}

type rawEntriesFetcher func(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool)

func (ls *LogStream) getGapEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	if ls.gapTile != nil {
		return ls.getTileEntriesWithClient(ctx, ls.gapTile, start, end, historical, handleFn, gapcounter)
	}
	return ls.getEntries(ctx, start, end, historical, handleFn, gapcounter)
}

func (e errLogEntriesTooOld) Error() string {
	return "log entries are older than " + strconv.Itoa(e.MaxAge) + " days"
}

func (e errLogEntriesTooOld) Unwrap() error {
	return ErrLogEntriesTooOld
}

func (cdb *PgDB) backfillGapsWithFetcher(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher, scanDone <-chan error) (scanErr error) {
	if cdb != nil && ls != nil {
		var lastgap gap
		var nullableMaxIndex sql.NullInt64
		lastindex := ls.LastIndex.Load()
		row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
		maxErr := cdb.LogError(row.Scan(&nullableMaxIndex), "backfillGapsWithFetcher/MaxIndex", "url", ls.URL())
		scanErr = maxErr
		if maxErr == nil {
			if nullableMaxIndex.Valid {
				ls.seeIndex(nullableMaxIndex.Int64)
				if lastindex < nullableMaxIndex.Int64 {
					lastindex = nullableMaxIndex.Int64
				}
				if nullableMaxIndex.Int64 < lastindex {
					lastgap = gap{start: nullableMaxIndex.Int64 + 1, end: lastindex}
					cdb.recordGap(ls, lastgap)
				}
			}
		}
		if gapCh := ls.getGapCh(); gapCh != nil {
			allGapsFilled := maxErr == nil
			fillGap := func(g gap) {
				if ctx.Err() == nil {
					ls.Backfill.Add((g.end - g.start) + 1)
					next, _ := fetchFn(ctx, g.start, g.end, true, ls.sendEntry, &ls.Backfill)
					if allGapsFilled {
						if err := cdb.backfillSetGapStartIndex(ctx, ls, next); err != nil {
							scanErr = errors.Join(scanErr, err)
							allGapsFilled = false
						}
					}
					if next < g.end+1 {
						allGapsFilled = false
					}
				} else {
					allGapsFilled = false
				}
			}
			for gap := range gapCh {
				fillGap(gap)
			}
			if scanDone != nil {
				scanErr = errors.Join(scanErr, <-scanDone)
				if scanErr != nil {
					allGapsFilled = false
				}
			}
			if lastgap.end != 0 {
				fillGap(lastgap)
			}
			if lastindex > 0 && allGapsFilled {
				scanErr = errors.Join(scanErr, cdb.backfillSetGapStartIndex(ctx, ls, lastindex))
			}
			if !allGapsFilled && scanErr == nil && ctx.Err() == nil {
				scanErr = errGapIncomplete
			}
		}
	}
	return
}

func (cdb *PgDB) scanAndBackfillGaps(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher) (scanErr error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()

	gapCh := make(chan gap, 8)
	ls.mu.Lock()
	ls.gapCh = gapCh
	ls.mu.Unlock()

	scanDone := make(chan error, 1)
	go func() {
		scanDone <- cdb.selectStreamGaps(ctx, ls)
	}()
	scanErr = cdb.backfillGapsWithFetcher(ctx, ls, fetchFn, scanDone)

	ls.mu.Lock()
	if ls.gapCh == gapCh {
		ls.gapCh = nil
	}
	ls.mu.Unlock()
	if err := ctx.Err(); err != nil {
		scanErr = errors.Join(scanErr, err)
	}
	if scanErr == nil {
		cdb.LogInfo("gap scan completed", "url", ls.URL(), "stream", ls.Id, "elapsed", time.Since(started).Round(time.Millisecond))
	}
	return
}

func nextGapScanAt(now time.Time, scanErr error) time.Time {
	if scanErr != nil && scanErr != errGapIncomplete {
		return now.Add(time.Minute)
	}
	return now.Add(24 * time.Hour)
}

func (cdb *PgDB) rescanGaps(ctx context.Context, ls *LogStream, next time.Time, wg *sync.WaitGroup) {
	defer wg.Done()
	for ctx.Err() == nil {
		if sleep(ctx, time.Until(next)) != nil {
			return
		}
		scanErr := cdb.scanAndBackfillGaps(ctx, ls, ls.getGapEntries)
		next = nextGapScanAt(time.Now(), scanErr)
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

func reverseBackfillStart(minIndex int64, tiled bool) int64 {
	if tiled {
		// Torchwood reads up to 50 whole data tiles at once. Keep reverse
		// windows on those boundaries so each tile is fetched only once.
		const window = 50 * sunlight.TileWidth
		return (minIndex - 1) / window * window
	}
	return max(0, minIndex-LogBatchSize)
}

func (cdb *PgDB) backfillStream(ctx context.Context, ls *LogStream, wg *sync.WaitGroup) {
	defer wg.Done()
	var minIndex int64
	var err error

	scanErr := cdb.scanAndBackfillGaps(ctx, ls, ls.getGapEntries)
	var scanWG sync.WaitGroup
	scanWG.Add(1)
	go cdb.rescanGaps(ctx, ls, nextGapScanAt(time.Now(), scanErr), &scanWG)
	defer scanWG.Wait()
	for ctx.Err() == nil {
		if minIndex, err = cdb.backfillMinIndex(ctx, ls); err == nil {
			break
		}
		if sleep(ctx, time.Minute) != nil {
			return
		}
	}
	if err == nil && minIndex > 0 {
		cdb.LogInfo("backlog start", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
		ls.Backfill.Add(minIndex)
		for minIndex > 0 && ctx.Err() == nil {
			start := reverseBackfillStart(minIndex, ls.isTiled())
			stop := minIndex - 1
			minIndex = start
			var wanted bool
			if _, wanted = ls.getEntries(ctx, start, stop, true, ls.sendEntry, &ls.Backfill); !wanted {
				ls.addError(ls, errLogEntriesTooOld{MaxAge: cdb.PgMaxAge})
				ls.Backfill.Add(-minIndex)
				break
			}
		}
		if ctx.Err() == nil {
			cdb.LogInfo("backlog stops", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
		}
	}
}
