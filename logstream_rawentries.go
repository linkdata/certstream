package certstream

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

func rawEntriesStopIndex(start, end int64, historical bool) (stop int64) {
	stop = start
	if start <= end {
		size := LogBatchSize
		if historical {
			size = max(16, LogBatchSize/32)
		}
		stop = start + min(end-start+1, size) - 1
	}
	return
}

// getRawEntries fetches and processes the logentries in the index range start...end (inclusive) in order with no parallelism.
// Returns 'wanted' set to true if handleFn returned true for any logentry.
// Returns an error if not all entries could be fetched and processed.
func (ls *LogStream) getRawEntries(ctx context.Context, client rawEntriesClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool, err error) {
	for start <= end && err == nil {
		stopIndex := rawEntriesStopIndex(start, end, historical)
		var resp *ct.GetEntriesResponse
		if err = ls.backoff.Retry(ctx, func() (e error) {
			ls.adjustTailLimiter(historical)
			if resp, e = client.GetRawEntries(ctx, start, stopIndex); e != nil {
				if !ls.handleStreamError(e, "GetRawEntries") {
					e = wrapLogStreamRetryable(e)
				}
			}
			return
		}); err == nil {
			now := time.Now()
			for i := range resp.Entries {
				le := ls.makeLogEntry(start, resp.Entries[i], historical)
				if handleFn(ctx, now, le) {
					wanted = true
				}
				ls.seeIndex(start)
				start++
				if gapcounter != nil {
					gapcounter.Add(-1)
				}
			}
		} else {
			if ctx.Err() == nil {
				_ = ls.LogError(err, "GetRawEntries", "url", ls.URL(), "start", start, "end", end)
			}
			if gapcounter != nil {
				gapcounter.Add(start - (end + 1))
			}
		}
	}
	return
}

// getRawEntriesParallel fetches and processes the logentries in the index range start...end (inclusive) using Config.Concurrency workers.
// The returned next start index can be less than end+1 if an error occured.
// Returns the next start index and 'wanted' set to true if handleFn returned true for any logentry.
func (ls *LogStream) getRawEntriesParallel(ctx context.Context, client rawEntriesClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	type rawEntriesRange struct {
		start int64
		end   int64
	}

	err := ctx.Err()
	next = start

	workCh := make(chan rawEntriesRange)
	workerCount := min(32, max(1, ls.Concurrency))
	completed := make(map[int64]int64)
	var wg sync.WaitGroup
	var workMu sync.Mutex
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range workCh {
				w, e := ls.getRawEntries(ctx, client, r.start, r.end, historical, handleFn, gapcounter)
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
				}
				workMu.Unlock()
			}
		}()
	}

	for start <= end && err == nil {
		stopIndex := rawEntriesStopIndex(start, end, historical)
		select {
		case workCh <- rawEntriesRange{start: start, end: stopIndex}:
			start = stopIndex + 1
		case <-ctx.Done():
			err = ctx.Err()
		}
	}

	close(workCh)
	wg.Wait()

	return
}
