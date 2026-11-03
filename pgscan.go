package certstream

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	gapWindowSize      int64 = 10_000
	gapProbeSize       int64 = 1_000_000
	gapRecentLookback  int64 = 1_000_000
	gapQueryTimeout          = 2 * time.Second
	gapProbeTimeout          = 500 * time.Millisecond
	gapRecentBudget          = 3 * time.Second
	gapColdBudget            = 3 * time.Second
	gapScanPassTimeout       = 10 * time.Second
	gapScanInterval          = 15 * time.Minute
	gapColdInterval          = 10 * time.Second
	gapRetryInterval         = time.Minute
)

var errGapScanDeferred = errors.New("gap scan deferred while database queue is busy")

type coldScanState struct {
	next int64 // next index to scan, or -1 for a new sweep
	end  int64 // fixed end of the current sweep, or -1 for a new sweep
}

func (cdb *PgDB) completeGapRange(ctx context.Context, stream int32, start, end int64) (complete bool, err error) {
	queryCtx, cancel := context.WithTimeout(ctx, gapProbeTimeout)
	defer cancel()
	var entries int64
	if err = cdb.QueryRow(queryCtx, cdb.stmtSelectGapCount, stream, start, end).Scan(&entries); err == nil {
		complete = entries == end-start+1
	} else if queryCtx.Err() != nil {
		err = queryCtx.Err()
	}
	return
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

func (cdb *PgDB) sendColdGapRange(ctx context.Context, ls *LogStream, gapCh chan gap, end int64, scanPos, cursor *int64, persist *bool) (err error) {
	scanWindows := false
	incomplete := false
	hi := end
	for *scanPos <= end {
		checkEnd := end
		if incomplete {
			checkEnd = *scanPos + (hi-*scanPos)/2
		}
		if scanWindows || checkEnd-*scanPos+1 <= gapWindowSize {
			checkEnd = min(end, *scanPos+gapWindowSize-1)
			var found bool
			found, *scanPos, err = cdb.sendGapWindow(ctx, ls, gapCh, *scanPos, checkEnd, cursor, *persist)
			if err != nil {
				return
			}
			if found {
				*persist = false
				// Bounded reads avoid recounting every prefix after a gap.
				scanWindows = true
			}
			incomplete = false
			hi = end
			continue
		}
		if cdb.QueueUsage() > 50 {
			return errGapScanDeferred
		}
		var complete bool
		complete, err = cdb.completeGapRange(ctx, ls.Id, *scanPos, checkEnd)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return
			}
			err = nil
			scanWindows = true
			continue
		}
		if !complete {
			// A short count keeps the first gap in this prefix.
			incomplete = true
			hi = checkEnd
			continue
		}
		if *persist {
			if err = cdb.backfillSetGapStartIndex(ctx, ls, checkEnd); err != nil {
				return
			}
			if err = ctx.Err(); err != nil {
				return
			}
			*cursor = checkEnd
		}
		*scanPos = checkEnd + 1
	}
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
		if scanErr != nil && !errors.Is(scanErr, context.Canceled) && !errors.Is(scanErr, errGapScanDeferred) {
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
	for end := maxIndex; scanRecent && end >= recentStart && scanErr == nil; {
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
	hotErr := scanErr
	hotBudgetExpired := errors.Is(recentCtx.Err(), context.DeadlineExceeded)
	cancel()
	if hotErr != nil && (ctx.Err() != nil || !errors.Is(hotErr, context.DeadlineExceeded)) {
		return
	}
	scanErr = nil
	if !hotBudgetExpired {
		defer func() {
			if scanErr == nil {
				scanErr = hotErr
			}
		}()
	}
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
			cold.next = -1
			cold.end = -1
		}
		return
	}
	if !scanRecent {
		// The cold pass also checks the recent tail between full recent scans.
		hotFloor = maxIndex + 1
	}
	coldEnd := hotFloor - 1
	coldCtx, cancel := context.WithTimeout(ctx, gapColdBudget)
	defer cancel()
	// A new sweep checks the cursor with one small read before probing ahead.
	scanPos := cursor
	scanEnd := coldEnd
	if cold != nil {
		if cold.end < 0 {
			cold.end = coldEnd
		}
		scanEnd = min(scanEnd, cold.end)
		if cold.next >= cursor && cold.next <= scanEnd {
			scanPos = cold.next
		}
		defer func() {
			cold.next = scanPos
			if scanPos > scanEnd {
				cold.next = -1
				cold.end = -1
			}
		}()
	}
	// Only a scan from the durable cursor may advance it.
	persist := scanPos == cursor
	if coldPending != nil {
		defer func() { *coldPending = cursor < coldEnd || firstGap >= 0 || !persist }()
	}
	if scanPos <= scanEnd {
		end := min(scanEnd, scanPos+gapWindowSize-1)
		var found bool
		found, scanPos, scanErr = cdb.sendGapWindow(coldCtx, ls, gapCh, scanPos, end, &cursor, persist)
		if scanErr != nil {
			return
		}
		if found {
			persist = false
		}
	}
	for scanPos <= scanEnd && scanErr == nil {
		end := min(scanEnd, scanPos+gapProbeSize-1)
		scanErr = cdb.sendColdGapRange(coldCtx, ls, gapCh, end, &scanPos, &cursor, &persist)
	}
	return
}
