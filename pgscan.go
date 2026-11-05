package certstream

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	gapWindowSize      int64 = 10_000
	gapColdChunkSize   int64 = 1_000_000
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
	errGapScanDeferred = errors.New("gap scan deferred while database queue is busy")
	errGapChannelFull  = errors.New("gap scan deferred while gap channel is full")
)

type coldScanState struct {
	next          int64 // next index to scan, or -1 for a new sweep
	end           int64 // fixed end of the current sweep, or -1 for a new sweep
	cursorBlocked bool  // the sweep cannot advance the durable cursor
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

func (cdb *PgDB) sendGapWindow(ctx context.Context, ls *LogStream, gapCh chan gap, start, end int64, cursor *int64, persist bool) (found bool, next int64, err error) {
	next = start
	if cdb.QueueUsage() > 50 {
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
		found = true
		next = g.start
		if err = cdb.queueGap(ctx, ls, gapCh, g, true); err != nil {
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
	if cdb.QueueUsage() > 50 {
		return errGapScanDeferred
	}
	select {
	case cdb.gapScanPermit <- struct{}{}:
		defer func() { <-cdb.gapScanPermit }()
	case <-ctx.Done():
		return ctx.Err()
	}
	ctx, cancelPass := context.WithTimeout(ctx, gapScanPassTimeout)
	defer cancelPass()
	if cdb.QueueUsage() > 50 {
		return errGapScanDeferred
	}
	var maxRow sql.NullInt64
	if scanErr = cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id).Scan(&maxRow); scanErr != nil || !maxRow.Valid {
		return
	}
	maxIndex := maxRow.Int64
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
	recentCtx, cancel := context.WithTimeout(ctx, gapRecentBudget)
	hotFloor := maxIndex + 1
	firstGap := int64(-1)
	for end := maxIndex; scanRecent && end >= recentStart; {
		start := max(recentStart, end-gapWindowSize+1)
		var gaps []gap
		if cdb.QueueUsage() > 50 {
			scanErr = errGapScanDeferred
			break
		}
		gaps, scanErr = cdb.storedGaps(recentCtx, ls.Id, start, end)
		if scanErr != nil {
			break
		}
		for _, g := range gaps {
			if firstGap < 0 || g.start < firstGap {
				firstGap = g.start
			}
			scanErr = cdb.queueGap(recentCtx, ls, gapCh, g, false)
			if scanErr != nil {
				break
			}
		}
		if scanErr != nil {
			break
		}
		hotFloor = start
		if start == 0 {
			break
		}
		end = start - 1
	}
	cancel()
	if scanErr != nil && (ctx.Err() != nil || !errors.Is(scanErr, context.DeadlineExceeded)) {
		return
	}
	scanErr = nil
	if firstGap >= 0 && firstGap < cursor {
		if _, scanErr = cdb.Exec(ctx, cdb.stmtLowerBackfillIdx, firstGap, ls.Id); scanErr != nil {
			return
		}
		cursor = firstGap
	}
	if cursor == 0 {
		if first.Valid && first.Int64 > 0 {
			// Reverse backfill owns the prefix before the first stored entry.
			if scanErr = cdb.backfillSetGapStartIndex(ctx, ls, first.Int64); scanErr != nil {
				return
			}
			cursor = first.Int64
		}
	}
	if scanRecent && recentCutoff == 0 && hotFloor == recentStart && cursor >= recentStart {
		verified := maxIndex
		if firstGap >= 0 {
			verified = firstGap
		}
		if verified > cursor {
			if scanErr = cdb.backfillSetGapStartIndex(ctx, ls, verified); scanErr != nil {
				return
			}
		}
		if coldPending != nil {
			*coldPending = firstGap >= 0
		}
		if cold != nil {
			*cold = coldScanState{next: -1, end: -1}
		}
		return
	}
	// Cold-only passes also cover the recent tail.
	coldEnd := hotFloor - 1
	coldStarted := time.Now()
	scanPos := cursor
	scanEnd := coldEnd
	// Persist only while the sweep has verified every index since the cursor.
	persist := true
	if cold != nil {
		if cold.end < 0 || cold.next < cursor || cold.next > min(coldEnd, cold.end) {
			*cold = coldScanState{next: cursor, end: coldEnd}
		}
		scanEnd = min(scanEnd, cold.end)
		scanPos = cold.next
		persist = scanPos == cursor || (!cold.cursorBlocked && scanPos == cursor+1)
		defer func() {
			cold.next = scanPos
			cold.cursorBlocked = !persist
			if scanPos > scanEnd {
				*cold = coldScanState{next: -1, end: -1}
			}
		}()
	}
	if coldPending != nil {
		defer func() { *coldPending = cursor < coldEnd || firstGap >= 0 || !persist }()
	}
	ls.GapScanIndex.Store(scanPos)
	// The first read is small and always starts; the budget limits later reads.
	firstRead := true
	for scanPos <= scanEnd && (firstRead || time.Since(coldStarted) < gapColdStartBudget) {
		size := gapColdChunkSize
		if firstRead {
			size = gapWindowSize
			firstRead = false
		}
		end := min(scanEnd, scanPos+size-1)
		var found bool
		found, scanPos, scanErr = cdb.sendGapWindow(ctx, ls, gapCh, scanPos, end, &cursor, persist)
		ls.GapScanIndex.Store(scanPos)
		if found {
			persist = false
		}
		if scanErr != nil {
			break
		}
	}
	return
}
