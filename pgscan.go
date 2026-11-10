package certstream

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"filippo.io/sunlight"
)

const (
	gapWindowSize      int64 = 10_000
	gapColdChunkSize   int64 = 100_000
	gapRecentLookback  int64 = 1_000_000
	gapQueryTimeout          = 5 * time.Minute
	gapRecentBudget          = 3 * time.Second
	gapColdStartBudget       = 3 * time.Second
	gapScanPassTimeout       = 6 * time.Minute
	gapScanInterval          = 15 * time.Minute
	gapColdInterval          = 10 * time.Second
	gapRetryInterval         = time.Minute
)

var (
	errGapScanDeferred = errors.New("gap scan deferred")
	errGapChannelFull  = errors.New("gap scan deferred while gap channel is full")
)

type coldScanState struct {
	next           int64 // next index to scan, or -1 for a new sweep
	end            int64 // fixed end of the current sweep, or -1 for a new sweep
	cursor         int64 // durable cursor observed after the last pass
	cursorBlocked  bool  // the sweep cannot advance the durable cursor
	retryResume    int64 // scan position saved for one prompt retry at the cursor
	retryDone      bool  // the sweep has retried its oldest unresolved gap
	recentComplete bool  // the last pass completed the recent scan
	wasContinuous  bool  // the last pass of this sweep used continuous mode
}

func (cdb *PgDB) storedGaps(ctx context.Context, stream int32, start, end int64) (gaps []gap, err error) {
	queryCtx, cancel := context.WithTimeout(ctx, gapQueryTimeout)
	defer cancel()
	rows, err := cdb.Query(queryCtx, cdb.stmtSelectGapWindow, stream, start, end)
	if err != nil {
		return nil, err
	}
	expected := start
	for rows.Next() {
		var index int64
		if err = rows.Scan(&index); err != nil {
			break
		}
		if index > expected {
			gaps = append(gaps, gap{start: expected, end: index - 1})
		}
		expected = index + 1
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err == nil && expected <= end {
		gaps = append(gaps, gap{start: expected, end: end})
	}
	if err != nil {
		gaps = nil
	}
	return
}

func (cdb *PgDB) sendGapWindow(ctx context.Context, ls *LogStream, gapCh chan gap, start, end int64, cursor *int64, persist, continuous bool) (found bool, next int64, err error) {
	next = start
	if continuous != ls.GapScanContinuous() || (!continuous && cdb.QueueUsage() > 50) {
		err = errGapScanDeferred
		return
	}
	var gaps []gap
	if gaps, err = cdb.storedGaps(ctx, ls.Id, start, end); err != nil {
		return
	}
	verified := end
	if len(gaps) > 0 {
		verified = gaps[0].start
	}
	if persist && verified > *cursor {
		if err = cdb.backfillSetGapStartIndex(ctx, ls, verified); err != nil {
			return
		}
		*cursor = verified
	}
	for _, g := range gaps {
		if continuous != ls.GapScanContinuous() {
			err = errGapScanDeferred
			return
		}
		found = true
		next = g.start
		if err = cdb.queueGap(ctx, ls, gapCh, g, !continuous, continuous); err != nil {
			return
		}
	}
	next = end + 1
	return
}

func (cdb *PgDB) selectStreamGaps(ctx context.Context, ls *LogStream) error {
	return cdb.selectStreamGapsMode(ctx, ls, nil, true, nil)
}

func (cdb *PgDB) selectStreamGapsMode(ctx context.Context, ls *LogStream, cold *coldScanState, scanRecent bool, coldPending *bool) (scanErr error) {
	return cdb.selectStreamGapsModeReady(ctx, ls, cold, scanRecent, coldPending, nil)
}

func (cdb *PgDB) selectStreamGapsModeReady(ctx context.Context, ls *LogStream, cold *coldScanState, scanRecent bool, coldPending *bool, ready chan<- bool) (scanErr error) {
	if ready != nil {
		defer close(ready)
	}
	recentComplete := false
	if cold != nil {
		defer func() { cold.recentComplete = recentComplete }()
	}
	continuous := ls.GapScanContinuous()
	if cold != nil && !continuous {
		cold.wasContinuous = false
	}
	gapCh := ls.getGapCh()
	if gapCh == nil {
		return nil
	}
	defer func() {
		ls.mu.Lock()
		if ls.gapCh == gapCh {
			close(gapCh)
		}
		ls.mu.Unlock()
		if scanErr != nil && !errors.Is(scanErr, context.Canceled) && !errors.Is(scanErr, errGapScanDeferred) && !errors.Is(scanErr, errGapChannelFull) {
			_ = cdb.LogError(scanErr, "selectStreamGaps", "stream", ls.Id, "url", ls.URL())
		}
	}()
	if !continuous && cdb.QueueUsage() > 50 {
		return errGapScanDeferred
	}
	if !continuous {
		acquired := false
		for !acquired {
			select {
			case cdb.gapScanPermit <- struct{}{}:
				acquired = true
				defer func() { <-cdb.gapScanPermit }()
			case <-ls.gapScanWakeCh():
				if continuous != ls.GapScanContinuous() {
					return errGapScanDeferred
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	parentCtx := ctx
	ctx, cancelPass := context.WithTimeout(ctx, gapScanPassTimeout)
	defer cancelPass()
	if continuous != ls.GapScanContinuous() {
		return errGapScanDeferred
	}
	if !continuous && cdb.QueueUsage() > 50 {
		return errGapScanDeferred
	}
	var maxRow sql.NullInt64
	if scanErr = cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id).Scan(&maxRow); scanErr != nil || !maxRow.Valid {
		return
	}
	maxIndex := maxRow.Int64
	ls.seeIndex(maxIndex)
	var cursor int64
	if scanErr = cdb.QueryRow(ctx, cdb.stmtSelectBackfillIdx, ls.Id).Scan(&cursor); scanErr != nil {
		return
	}
	recentCutoff := max(int64(0), maxIndex-gapRecentLookback+1)
	recentStart := recentCutoff
	var first sql.NullInt64
	if scanErr = cdb.QueryRow(ctx, cdb.stmtSelectMinIdx, ls.Id).Scan(&first); scanErr != nil {
		return
	}
	if first.Valid && first.Int64 > recentStart {
		recentStart = first.Int64
	}
	if cursor == 0 && first.Valid && first.Int64 > 0 {
		// Reverse backfill owns the prefix before the first stored entry.
		if scanErr = cdb.backfillSetGapStartIndex(ctx, ls, first.Int64); scanErr != nil {
			return
		}
		cursor = first.Int64
	}
	// Cold gaps precede recent gaps in the fetch queue. Resume an unfinished
	// cold sweep before considering the recent tail.
	if cursor < recentStart || (cold != nil && cold.next >= 0) {
		scanRecent = false
	}
	recentCtx, cancel := context.WithTimeout(ctx, gapRecentBudget)
	hotFloor := recentStart
	firstGap := int64(-1)
	for start := recentStart; scanRecent && start <= maxIndex; {
		end := min(maxIndex, start+gapWindowSize-1)
		var gaps []gap
		if continuous != ls.GapScanContinuous() || (!continuous && cdb.QueueUsage() > 50) {
			scanErr = errGapScanDeferred
			break
		}
		gaps, scanErr = cdb.storedGaps(recentCtx, ls.Id, start, end)
		if scanErr != nil {
			break
		}
		for _, g := range gaps {
			if continuous != ls.GapScanContinuous() {
				scanErr = errGapScanDeferred
				break
			}
			if firstGap < 0 {
				firstGap = g.start
			}
			if g.start < cursor {
				if _, scanErr = cdb.Exec(ctx, cdb.stmtLowerBackfillIdx, g.start, ls.Id); scanErr != nil {
					break
				}
				cursor = g.start
			}
			scanErr = cdb.queueGap(recentCtx, ls, gapCh, g, false, continuous)
			if scanErr != nil {
				break
			}
			hotFloor = g.end + 1
		}
		if scanErr != nil {
			break
		}
		hotFloor = end + 1
		start = hotFloor
	}
	cancel()
	if scanErr != nil && (ctx.Err() != nil || !errors.Is(scanErr, context.DeadlineExceeded)) {
		return
	}
	scanErr = nil
	if firstGap > cursor {
		if scanErr = cdb.backfillSetGapStartIndex(ctx, ls, firstGap); scanErr != nil {
			return
		}
		cursor = firstGap
	}
	if scanRecent && hotFloor > maxIndex {
		if firstGap < 0 && maxIndex > cursor {
			if scanErr = cdb.backfillSetGapStartIndex(ctx, ls, maxIndex); scanErr != nil {
				return
			}
		}
		if coldPending != nil {
			*coldPending = firstGap >= 0
		}
		if cold != nil {
			*cold = coldScanState{next: -1, end: -1}
		}
		if continuous {
			ls.SetGapScanContinuous(false)
		}
		recentComplete = true
		return
	}
	// Cold-only passes cover the recent tail when an older gap remains.
	coldEnd := maxIndex
	coldStarted := time.Now()
	scanPos := cursor
	if scanRecent {
		scanPos = hotFloor
		if firstGap < 0 && hotFloor-1 > cursor {
			if scanErr = cdb.backfillSetGapStartIndex(ctx, ls, hotFloor-1); scanErr != nil {
				return
			}
			cursor = hotFloor - 1
		}
	}
	scanEnd := coldEnd
	// Persist only while the sweep has verified every index since the cursor.
	persist := !scanRecent || firstGap < 0
	if cold != nil {
		if cold.end < 0 || cold.cursor != cursor || cold.next < cursor || cold.next > min(coldEnd, cold.end) || (continuous && !cold.wasContinuous) {
			// A continuous sweep covers the durable cursor, including any shared-mode prefix.
			*cold = coldScanState{next: scanPos, end: coldEnd, cursor: cursor, wasContinuous: continuous}
		}
		scanEnd = min(scanEnd, cold.end)
		scanPos = cold.next
		persist = persist && (scanPos == cursor || (!cold.cursorBlocked && scanPos == cursor+1))
	}
	if ready != nil {
		ready <- persist
	}
	defer func() {
		if cold != nil {
			cold.next = scanPos
			cold.cursor = cursor
			cold.cursorBlocked = !persist
			if scanPos > scanEnd {
				*cold = coldScanState{next: -1, end: -1}
			}
		}
		if continuous && scanErr == nil && scanPos > scanEnd {
			ls.SetGapScanContinuous(false)
		}
	}()
	if coldPending != nil {
		defer func() { *coldPending = cursor < coldEnd || firstGap >= 0 || !persist }()
	}
	ls.GapScanIndex.Store(scanPos)
	// The first read is small and always starts; the budget limits later reads.
	firstRead := true
	passStart := scanPos
	for scanPos <= scanEnd && (continuous || firstRead || time.Since(coldStarted) < gapColdStartBudget) {
		if continuous != ls.GapScanContinuous() {
			scanErr = errGapScanDeferred
			break
		}
		size := gapColdChunkSize
		if firstRead {
			size = gapWindowSize
			firstRead = false
		}
		end := min(scanEnd, scanPos+size-1)
		if end < scanEnd {
			aligned := end - (end+1)%sunlight.TileWidth
			if aligned >= scanPos {
				end = aligned
			}
		}
		var found bool
		found, scanPos, scanErr = cdb.sendGapWindow(ctx, ls, gapCh, scanPos, end, &cursor, persist, continuous)
		ls.GapScanIndex.Store(scanPos)
		if found {
			persist = false
		}
		if scanErr != nil {
			break
		}
	}
	if continuous && scanPos > passStart && parentCtx.Err() == nil && errors.Is(scanErr, context.DeadlineExceeded) && ctx.Err() == context.DeadlineExceeded {
		scanErr = errGapScanDeferred
	}
	return
}
