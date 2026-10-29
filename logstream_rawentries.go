package certstream

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

func rawEntriesStopIndex(start, end int64) (stop int64) {
	stop = start
	if start <= end {
		// End each window at a common boundary so truncated responses can
		// bring the next request onto a cacheable full-size range.
		stop = start + min(end-start+1, LogBatchSize-start%LogBatchSize) - 1
	}
	return
}

// getRawEntries fetches and processes the logentries in the index range start...end (inclusive) in order with no parallelism.
// Returns 'wanted' set to true if handleFn returned true for any logentry.
// Returns an error if not all entries could be fetched and processed.
func (ls *LogStream) getRawEntries(ctx context.Context, client rawEntriesClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool, next int64, err error) {
	next = start
	for next <= end && err == nil {
		stopIndex := rawEntriesStopIndex(next, end)
		var resp *ct.GetEntriesResponse
		if err = ls.backoff.Retry(ctx, func() (e error) {
			if ls.LogOperator != nil {
				if sleeptime := min(500, ls.Status429.Load()*2); sleeptime > 0 {
					if historical {
						sleeptime *= 2
					}
					_ = sleep(ctx, time.Millisecond*time.Duration(sleeptime))
				}
			}
			if e = ls.waitForQueue(ctx, historical); e != nil {
				return
			}
			if resp, e = client.GetRawEntries(ctx, next, stopIndex); e != nil {
				if !ls.handleStreamError(e, "GetRawEntries") {
					e = wrapLogStreamRetryable(e)
				}
			}
			return
		}); err == nil {
			now := time.Now()
			for i := range resp.Entries {
				if historical {
					if err = ls.waitForQueue(ctx, true); err != nil {
						break
					}
					now = time.Now()
				}
				le := ls.makeLogEntry(next, resp.Entries[i], historical)
				if handleFn(ctx, now, le) {
					wanted = true
				}
				ls.seeIndex(next)
				next++
				if gapcounter != nil {
					gapcounter.Add(-1)
				}
			}
		}
		if err != nil {
			if ctx.Err() == nil {
				_ = ls.LogError(err, "GetRawEntries", "url", ls.URL(), "start", next, "end", end)
			}
			if gapcounter != nil {
				gapcounter.Add(next - (end + 1))
			}
		}
	}
	return
}

// getRawEntriesParallel fetches and processes log entries in parallel.
//
// It uses the provider's configured concurrency for the inclusive index range.
// The returned next start index can be less than end+1 if an error occurred.
// Returns the next start index and 'wanted' set to true if handleFn returned true for any logentry.
func (ls *LogStream) getRawEntriesParallel(ctx context.Context, client rawEntriesClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool, next int64, err error) {
	type rawEntriesRange struct {
		start int64
		end   int64
	}

	err = ctx.Err()
	next = start

	sleepCtx, sleepCancel := context.WithCancel(ctx)
	workCh := make(chan rawEntriesRange)
	completed := make(map[int64]int64)
	var wg sync.WaitGroup
	var workMu sync.Mutex
	var stop atomic.Bool
	workerCount := 0
	startWorkers := func(limit int) {
		for workerCount < min(32, limit) {
			i := workerCount
			workerCount++
			wg.Add(1)
			go func() {
				defer wg.Done()
				if i > 0 && ls.Status429.Load() > 0 {
					_ = sleep(sleepCtx, time.Second/time.Duration(limit)*time.Duration(i))
				}
				for r := range workCh {
					w, _, e := ls.getRawEntries(ctx, client, r.start, r.end, historical, handleFn, gapcounter)
					workMu.Lock()
					wanted = wanted || w
					if e == nil {
						completed[r.start] = r.end
					advanceNext:
						if end, ok := completed[next]; ok {
							delete(completed, next)
							next = end + 1
							goto advanceNext
						}
					} else {
						err = e
						stop.Store(true)
					}
					workMu.Unlock()
				}
			}()
		}
	}
	limit, changed := ls.concurrencyChange()
	startWorkers(limit)

	for start <= end && ctx.Err() == nil && !stop.Load() {
		stopIndex := rawEntriesStopIndex(start, end)
		select {
		case workCh <- rawEntriesRange{start: start, end: stopIndex}:
			start = stopIndex + 1
		case <-changed:
			limit, changed = ls.concurrencyChange()
			startWorkers(limit)
		case <-ctx.Done():
		}
	}

	close(workCh)
	sleepCancel()
	wg.Wait()
	if err == nil {
		err = ctx.Err()
	}

	return
}
