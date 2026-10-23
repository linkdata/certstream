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
	return cdb.backfillGapsWithFetcherMode(ctx, ls, fetchFn, scanDone, true)
}

func (cdb *PgDB) backfillGapsWithFetcherMode(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher, scanDone <-chan error, includeTrailing bool) (scanErr error) {
	if cdb != nil && ls != nil {
		var lastgap gap
		var maxErr error
		if includeTrailing {
			var nullableMaxIndex sql.NullInt64
			lastindex := ls.LastIndex.Load()
			row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
			maxErr = cdb.LogError(row.Scan(&nullableMaxIndex), "backfillGapsWithFetcher/MaxIndex", "url", ls.URL())
			if maxErr == nil && nullableMaxIndex.Valid {
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
		scanErr = maxErr
		if gapCh := ls.getGapCh(); gapCh != nil {
			allGapsFilled := maxErr == nil
			fillGap := func(g gap) {
				if ctx.Err() == nil {
					ls.Backfill.Add((g.end - g.start) + 1)
					next, _ := fetchFn(ctx, g.start, g.end, true, ls.sendEntry, &ls.Backfill)
					// Fetched entries enter a queue; only a later DB scan proves they were stored.
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
			if !allGapsFilled && scanErr == nil && ctx.Err() == nil {
				scanErr = errGapIncomplete
			}
		}
	}
	return
}

func (cdb *PgDB) scanAndBackfillGaps(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher) (scanErr error) {
	return cdb.scanAndBackfillGapsMode(ctx, ls, fetchFn, true)
}

func (cdb *PgDB) scanAndBackfillGapsMode(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher, includeTrailing bool) (scanErr error) {
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
	scanErr = cdb.backfillGapsWithFetcherMode(ctx, ls, fetchFn, scanDone, includeTrailing)

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

func (cdb *PgDB) rescanGaps(ctx context.Context, ls *LogStream, next time.Time, wg *sync.WaitGroup) {
	defer wg.Done()
	for ctx.Err() == nil {
		if sleep(ctx, time.Until(next)) != nil {
			return
		}
		_ = cdb.scanAndBackfillGapsMode(ctx, ls, ls.getGapEntries, false)
		if err := cdb.recoverTrailingGap(ctx, ls, ls.getGapEntries); err != nil && !errors.Is(err, errGapScanDeferred) {
			_ = cdb.LogError(err, "recoverTrailingGap", "url", ls.URL())
		}
		next = time.Now().Add(gapScanInterval)
	}
}

func (cdb *PgDB) recoverTrailingGap(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher) (err error) {
	if cdb.QueueUsage() > 50 {
		return errGapScanDeferred
	}
	queryCtx, cancel := context.WithTimeout(ctx, gapQueryTimeout)
	defer cancel()
	var row sql.NullInt64
	if err = cdb.QueryRow(queryCtx, cdb.stmtSelectMaxIdx, ls.Id).Scan(&row); err != nil {
		return
	}
	storedMax := row.Int64
	if !row.Valid {
		if firstFetched := ls.MinIndex.Load(); firstFetched >= 0 {
			storedMax = firstFetched - 1
		} else {
			return
		}
	}
	head := ls.MaxIndex.Load()
	ls.mu.Lock()
	stable := ls.tailCheckValid && ls.tailCheckMax == storedMax
	ls.tailCheckMax = storedMax
	ls.tailCheckValid = true
	ls.mu.Unlock()
	if !stable || head <= storedMax {
		return
	}
	end := min(head, storedMax+gapWindowSize)
	ls.Backfill.Add(end - storedMax)
	next, _ := fetchFn(ctx, storedMax+1, end, true, ls.sendEntry, &ls.Backfill)
	if next <= end {
		err = errGapIncomplete
	}
	return
}

// Return the minimum stored log index, or -1 when the stream has no entries.
func (cdb *PgDB) backfillMinIndex(ctx context.Context, ls *LogStream) (minIndex int64, err error) {
	minIndex = -1
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

	_ = cdb.scanAndBackfillGaps(ctx, ls, ls.getGapEntries)
	var scanWG sync.WaitGroup
	scanWG.Add(1)
	go cdb.rescanGaps(ctx, ls, time.Now().Add(gapScanInterval), &scanWG)
	defer scanWG.Wait()
	for ctx.Err() == nil {
		if minIndex, err = cdb.backfillMinIndex(ctx, ls); err == nil {
			break
		}
		if sleep(ctx, time.Minute) != nil {
			return
		}
	}
	if minIndex < 0 {
		// An empty database still needs the entries preceding the known head.
		minIndex = ls.LastIndex.Load() + 1
	}
	if err == nil && minIndex > 0 {
		cdb.LogInfo("backlog start", "url", ls.URL(), "stream", ls.Id, "logindex", minIndex)
		ls.Backfill.Add(minIndex)
		for minIndex > 0 && ctx.Err() == nil {
			start := reverseBackfillStart(minIndex, ls.isTiled())
			stop := minIndex - 1
			next := start
			wanted := false
			retryDelay := time.Second
			for next <= stop && ctx.Err() == nil {
				fetched, windowWanted := ls.getEntries(ctx, next, stop, true, ls.sendEntry, &ls.Backfill)
				wanted = wanted || windowWanted
				if fetched <= stop {
					if ctx.Err() != nil {
						return
					}
					// Fetchers remove the unfetched remainder from Backfill on error.
					ls.Backfill.Add(stop + 1 - fetched)
					if fetched > next {
						retryDelay = time.Second
					} else {
						retryDelay = min(retryDelay*2, 30*time.Second)
					}
					if sleep(ctx, retryDelay) != nil {
						return
					}
				}
				next = fetched
			}
			if ctx.Err() != nil {
				return
			}
			minIndex = start
			if !wanted {
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
