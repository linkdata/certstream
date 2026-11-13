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

type gapGroup struct {
	start   int64
	end     int64
	gaps    []gap
	missing int64
	full    bool
}

const classicGapBatchTiles = 4 // bounds decoded entries per gap batch to 1024

func (ls *LogStream) getGapEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	return ls.getGapEntriesMode(ctx, start, end, historical, handleFn, gapcounter, true)
}

func (ls *LogStream) getTrailingGapEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	return ls.getGapEntriesMode(ctx, start, end, historical, handleFn, gapcounter, false)
}

func (ls *LogStream) getGapEntriesMode(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64, stopAfterProgress bool) (next int64, wanted bool) {
	if ls.gapTile != nil {
		return ls.getGapTileEntries(ctx, ls.gapTile, start, end, historical, handleFn, gapcounter)
	}
	if ls.isTiled() {
		client := ls.headTile
		if historical && ls.tailTile != nil {
			client = ls.tailTile
		}
		return ls.getGapTileEntries(ctx, client, start, end, historical, handleFn, gapcounter)
	}
	client := ls.headClient
	if ls.tailClient != nil {
		client = ls.tailClient
	}
	// Grouped scans return partial progress so earlier tiles can commit.
	wanted, next, _ = ls.getRawEntriesSized(ctx, client, start, end, historical, handleFn, gapcounter,
		sunlight.TileWidth, stopAfterProgress && end-start+1 > sunlight.TileWidth)
	return
}

func (cdb *PgDB) queueGap(ctx context.Context, ls *LogStream, gapCh chan gap, g gap, deferOnFull, continuous bool) (err error) {
	length := g.end - g.start + 1
	ls.Backfill.Add(length)
	if deferOnFull {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case gapCh <- g:
		default:
			err = errGapChannelFull
		}
	} else {
		queued := false
		for !queued && err == nil {
			if continuous != ls.GapScanContinuous() {
				err = errGapScanDeferred
				break
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case gapCh <- g:
				queued = true
			case <-ls.gapScanWakeCh():
				if continuous != ls.GapScanContinuous() {
					err = errGapScanDeferred
				}
			}
		}
	}
	if err == nil {
		cdb.recordGap(ls, g)
	} else {
		ls.Backfill.Add(-length)
	}
	return
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
	scanErr = cdb.backfillGapsWithFetcherCursor(ctx, ls, fetchFn, scanDone, includeTrailing, true)
	return
}

func (cdb *PgDB) backfillGapsWithFetcherCursor(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher, scanDone <-chan error, includeTrailing, cursorReady bool) (scanErr error) {
	if cdb != nil && ls != nil {
		if ls.isTiled() {
			ls.resetGapTileReader()
			defer ls.resetGapTileReader()
		}
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
			if lastgap.end != 0 {
				ls.Backfill.Add(lastgap.end - lastgap.start + 1)
			}
			storeDirect := ls.LogOperator != nil && ls.CertStream != nil && ls.DB() == cdb && cdb.Pool != nil
			cacheDecoded := !ls.isTiled()
			cachedGroupStart := int64(-1)
			var cachedEntries []*LogEntry
			fetchGroup := func(group gapGroup, advanceCursor bool) (commit func()) {
				if ctx.Err() != nil {
					ls.Backfill.Add(-group.missing)
					commit = func() {
						allGapsFilled = false
						cursorReady = false
					}
					return
				}
				seen := make([]bool, int(group.end-group.start+1))
				var entries []*LogEntry
				gapIndex := 0
				handle := func(ctx context.Context, now time.Time, le *LogEntry) bool {
					if le == nil {
						return false
					}
					index := le.Index()
					for gapIndex < len(group.gaps) && group.gaps[gapIndex].end < index {
						gapIndex++
					}
					if gapIndex >= len(group.gaps) || index < group.gaps[gapIndex].start {
						return false
					}
					position := int(index - group.start)
					if seen[position] {
						return false
					}
					if storeDirect {
						wanted, store := ls.prepareEntry(ctx, now, le)
						if store {
							seen[position] = true
							entries = append(entries, le)
						}
						return wanted
					}
					seen[position] = true
					return ls.sendEntry(ctx, now, le)
				}
				cached := cacheDecoded && cachedGroupStart == group.start
				if cached {
					for _, g := range group.gaps {
						for index := g.start; index <= g.end; index++ {
							position := int(index - group.start)
							if position >= len(cachedEntries) || cachedEntries[position] == nil ||
								(cachedEntries[position].Certificate == nil && cachedEntries[position].Err == nil) {
								cached = false
								break
							}
						}
						if !cached {
							break
						}
					}
				}
				var next int64
				if cached {
					next = group.gaps[len(group.gaps)-1].end + 1
					for _, g := range group.gaps {
						for index := g.start; index <= g.end; index++ {
							handle(ctx, time.Now(), cachedEntries[index-group.start])
						}
					}
				} else {
					var remaining atomic.Int64
					fetchHandle := handle
					if cacheDecoded {
						cachedGroupStart = group.start
						cachedEntries = make([]*LogEntry, group.end-group.start+1)
						fetchHandle = func(ctx context.Context, now time.Time, le *LogEntry) bool {
							if le != nil && le.Index() >= group.start && le.Index() <= group.end {
								cachedEntries[le.Index()-group.start] = le
							}
							return handle(ctx, now, le)
						}
					}
					start := group.start
					if ls.isTiled() {
						start = group.gaps[0].start
					}
					remaining.Store(group.end - start + 1)
					next, _ = fetchFn(ctx, start, group.end, true, fetchHandle, &remaining)
				}
				ls.Backfill.Add(-group.missing)
				commit = func() {
					cursorTarget := func() int64 {
						for _, g := range group.gaps {
							for index := g.start; index <= g.end; index++ {
								position := index - group.start
								if !seen[position] {
									return index
								}
							}
						}
						return group.gaps[len(group.gaps)-1].end + 1
					}
					lastCursorTarget := int64(-1)
					writeCursor := func(target int64) {
						if cursorReady && advanceCursor && target > lastCursorTarget {
							if err := cdb.backfillSetGapStartIndex(ctx, ls, target); err != nil {
								scanErr = errors.Join(scanErr, err)
								cursorReady = false
							} else {
								lastCursorTarget = target
							}
						}
					}
					var stored []bool
					if storeDirect && len(entries) > 0 {
						// After fetching, seen tracks entries committed by each SHA batch.
						for _, le := range entries {
							seen[le.Index()-group.start] = false
						}
						var err error
						stored, err = cdb.runGapBatches(ctx, entries, func(indexes []int) {
							for _, i := range indexes {
								seen[entries[i].Index()-group.start] = true
							}
							// The cursor follows the contiguous committed prefix as
							// SHA batches finish.
							if target := cursorTarget(); target > group.gaps[0].start {
								writeCursor(target)
							}
						})
						for i, le := range entries {
							if !stored[i] {
								if le.Certificate != nil {
									ls.Count.Add(-1)
									ls.LogOperator.Count.Add(-1)
								}
							}
						}
						if err != nil {
							scanErr = errors.Join(scanErr, cdb.LogError(err, "backfill gap batch", "stream", ls.Id, "start", group.start, "end", group.end))
						}
					}
					complete := next > group.gaps[len(group.gaps)-1].end
					target := group.gaps[len(group.gaps)-1].end + 1
					if storeDirect {
						target = cursorTarget()
						complete = complete && target > group.gaps[len(group.gaps)-1].end
					}
					if !complete {
						allGapsFilled = false
					}
					if storeDirect && len(entries) > 0 {
						writeCursor(target)
						for i, le := range entries {
							if stored[i] && le.Certificate != nil {
								if ch := cdb.getSendEntryCh(); ch != nil {
									select {
									case <-ctx.Done():
									case ch <- le:
									}
								}
							}
						}
					}
					if !complete || !storeDirect || !advanceCursor {
						cursorReady = false
					}
				}
				return
			}
			// One commit overlaps the next fetch; joins keep cursor updates in gap order.
			var commitDone chan struct{}
			waitCommit := func() {
				if commitDone != nil {
					<-commitDone
					commitDone = nil
				}
			}
			var group gapGroup
			flushGroup := func(advanceCursor bool) {
				if len(group.gaps) > 0 {
					commit := fetchGroup(group, advanceCursor)
					waitCommit()
					if storeDirect {
						done := make(chan struct{})
						commitDone = done
						go func() {
							defer close(done)
							commit()
						}()
					} else {
						commit()
					}
					group = gapGroup{}
				}
			}
			appendGap := func(g gap, advanceCursor bool) {
				for start := g.start; start <= g.end; {
					tileStart := start / sunlight.TileWidth * sunlight.TileWidth
					tileEnd := tileStart + sunlight.TileWidth - 1
					partEnd := min(g.end, tileEnd)
					full := start == tileStart && partEnd == tileEnd
					if len(group.gaps) > 0 && group.start != tileStart {
						// Only whole adjacent classic tiles share a DB batch. Partial
						// tiles keep their decoded cache and never fetch extra ranges.
						if ls.isTiled() || !group.full || !full || group.end+1 != tileStart ||
							tileStart-group.start >= classicGapBatchTiles*sunlight.TileWidth {
							flushGroup(advanceCursor)
						}
					}
					if len(group.gaps) == 0 {
						end := partEnd
						if !ls.isTiled() {
							end = min(tileEnd, max(g.end, ls.LastIndex.Load(), ls.MaxIndex.Load()))
						}
						group = gapGroup{
							start: tileStart,
							end:   end,
							full:  full,
						}
					}
					group.end = max(group.end, partEnd)
					group.gaps = append(group.gaps, gap{start: start, end: partEnd})
					group.missing += partEnd - start + 1
					start = partEnd + 1
				}
			}
			for {
				var g gap
				var ok bool
				select {
				case g, ok = <-gapCh:
				default:
					flushGroup(true)
					g, ok = <-gapCh
				}
				if !ok {
					break
				}
				appendGap(g, true)
			}
			flushGroup(true)
			waitCommit()
			if scanDone != nil {
				scanErr = errors.Join(scanErr, <-scanDone)
				if scanErr != nil {
					allGapsFilled = false
				}
			}
			if lastgap.end != 0 {
				// Startup trailing gaps are best effort; ongoing recovery retries them.
				appendGap(lastgap, false)
				flushGroup(false)
			}
			waitCommit()
			if !allGapsFilled && scanErr == nil && ctx.Err() == nil {
				scanErr = errGapIncomplete
			}
		}
	}
	return
}

func (cdb *PgDB) scanAndBackfillGaps(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher) (scanErr error) {
	return cdb.scanAndBackfillGapsMode(ctx, ls, fetchFn, true, nil, true, nil)
}

func (cdb *PgDB) scanAndBackfillGapsMode(ctx context.Context, ls *LogStream, fetchFn rawEntriesFetcher, includeTrailing bool, cold *coldScanState, scanRecent bool, coldPending *bool) (scanErr error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()

	gapQueueSize := 8
	if ls.GapScanContinuous() {
		// A cold window can contain thousands of short gaps.
		gapQueueSize = 4096
	}
	gapCh := make(chan gap, gapQueueSize)
	ls.mu.Lock()
	ls.gapCh = gapCh
	ls.mu.Unlock()

	cursorReady := cold == nil || !cold.cursorBlocked || cold.next <= cold.cursor
	var ready chan bool
	if !cursorReady {
		// A blocked sweep can restart at a newer durable cursor.
		ready = make(chan bool, 1)
	}
	scanDone := make(chan error, 1)
	go func() {
		scanDone <- cdb.selectStreamGapsModeReady(ctx, ls, cold, scanRecent, coldPending, ready)
	}()
	if ready != nil {
		cursorReady = <-ready
	}
	scanErr = cdb.backfillGapsWithFetcherCursor(ctx, ls, fetchFn, scanDone, includeTrailing, cursorReady)
	if cold != nil {
		if cold.retryResume > 0 {
			if cold.next > cold.cursor {
				if cold.cursorBlocked {
					cold.next = max(cold.next, cold.retryResume)
					cold.retryDone = true
				}
				cold.retryResume = 0
			}
		} else if cold.cursorBlocked && !cold.retryDone && cold.next > cold.cursor {
			// Retry the oldest gap once, then continue this sweep if it still fails.
			cold.retryResume = cold.next
			cold.next = cold.cursor
			cold.cursorBlocked = false
		}
	}

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
	nextHot := next
	nextCold := time.Now().Add(gapColdInterval)
	cold := coldScanState{next: -1, end: -1}
	for ctx.Err() == nil {
		next = nextHot
		if nextCold.Before(next) {
			next = nextCold
		}
		if delay := time.Until(next); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			case <-ls.gapScanWakeCh():
				if !ls.GapScanContinuous() {
					timer.Stop()
					continue
				}
			}
			timer.Stop()
		}
		scanRecent := !time.Now().Before(nextHot)
		var coldPending bool
		scanErr := cdb.scanAndBackfillGapsMode(ctx, ls, ls.getGapEntries, false, &cold, scanRecent, &coldPending)
		if err := cdb.recoverTrailingGap(ctx, ls, ls.getTrailingGapEntries); err != nil && !errors.Is(err, errGapScanDeferred) {
			_ = cdb.LogError(err, "recoverTrailingGap", "url", ls.URL())
		}
		hotIncomplete := scanRecent && !cold.recentComplete
		if scanRecent {
			if errors.Is(scanErr, errGapScanDeferred) || hotIncomplete {
				nextHot = time.Now().Add(gapColdInterval)
			} else {
				nextHot = time.Now().Add(gapScanInterval)
			}
		}
		// Continue unfinished sweeps promptly, but back off after a full sweep.
		if coldPending && cold.next < 0 {
			nextCold = time.Now().Add(gapRetryInterval)
		} else if scanErr != nil || coldPending {
			nextCold = time.Now().Add(gapColdInterval)
			if ls.GapScanContinuous() && (scanErr == nil || errors.Is(scanErr, errGapScanDeferred) || errors.Is(scanErr, errGapChannelFull)) {
				nextCold = time.Now()
			}
		} else {
			nextCold = nextHot
		}
		if hotIncomplete && nextHot.Before(nextCold) {
			nextHot = nextCold
		}
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
	missing := end - storedMax
	fetchStart := (storedMax + 1) / sunlight.TileWidth * sunlight.TileWidth
	fetchEnd := min(head, end/sunlight.TileWidth*sunlight.TileWidth+sunlight.TileWidth-1)
	ls.Backfill.Add(missing)
	var remaining atomic.Int64
	remaining.Store(fetchEnd - fetchStart + 1)
	handle := func(ctx context.Context, now time.Time, le *LogEntry) bool {
		if le != nil && le.Index() > storedMax && le.Index() <= end {
			return ls.sendEntry(ctx, now, le)
		}
		return false
	}
	if ls.isTiled() {
		defer ls.resetGapTileReader()
	}
	next, _ := fetchFn(ctx, fetchStart, fetchEnd, true, handle, &remaining)
	ls.Backfill.Add(-missing)
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
		if err = ctx.Err(); err == nil {
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
	// The age cutoff is decided once per reverse window. Keep at least
	// 1024 entries in each window when available, then align its start.
	window := max(int64(1024), LogBatchSize)
	return max(0, (minIndex-window)/LogBatchSize*LogBatchSize)
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
