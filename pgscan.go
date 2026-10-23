package certstream

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	gapWindowSize      int64 = 10_000
	gapRecentLookback  int64 = 1_000_000
	gapQueryTimeout          = 2 * time.Second
	gapRecentBudget          = 3 * time.Second
	gapColdBudget            = 3 * time.Second
	gapScanPassTimeout       = 10 * time.Second
	gapScanInterval          = 15 * time.Minute
)

var errGapScanDeferred = errors.New("gap scan deferred while database queue is busy")

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

func (cdb *PgDB) sendGapWindow(ctx context.Context, ls *LogStream, gapCh chan gap, start, end int64, cursor *int64) (found bool, err error) {
	if cdb.QueueUsage() > 50 {
		return false, errGapScanDeferred
	}
	var gaps []gap
	if gaps, err = cdb.storedGaps(ctx, ls.Id, start, end); err != nil {
		return
	}
	verified := end
	if len(gaps) > 0 {
		verified = gaps[0].start
	}
	if verified > *cursor {
		if err = cdb.backfillSetGapStartIndex(ctx, ls, verified); err != nil {
			return
		}
		*cursor = verified
	}
	for _, g := range gaps {
		found = true
		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		case gapCh <- g:
			cdb.recordGap(ls, g)
		}
	}
	return
}

func (cdb *PgDB) selectStreamGaps(ctx context.Context, ls *LogStream) (scanErr error) {
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
	for end := maxIndex; end >= recentStart && scanErr == nil; {
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
			select {
			case <-recentCtx.Done():
				scanErr = recentCtx.Err()
			case gapCh <- g:
				cdb.recordGap(ls, g)
			}
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
	if recentCutoff == 0 && hotFloor == recentStart && cursor >= recentStart {
		verified := maxIndex
		if firstGap >= 0 {
			verified = firstGap
		}
		if verified > cursor {
			if scanErr = cdb.backfillSetGapStartIndex(ctx, ls, verified); scanErr != nil {
				return
			}
		}
		return
	}
	coldEnd := hotFloor - 1
	coldCtx, cancel := context.WithTimeout(ctx, gapColdBudget)
	defer cancel()
	for cursor <= coldEnd && scanErr == nil {
		if cdb.QueueUsage() > 50 {
			return errGapScanDeferred
		}
		end := min(coldEnd, cursor+gapWindowSize-1)
		var found bool
		found, scanErr = cdb.sendGapWindow(coldCtx, ls, gapCh, cursor, end, &cursor)
		if found || end == coldEnd {
			break
		}
		cursor = end + 1
	}
	return
}
