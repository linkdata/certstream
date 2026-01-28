package certstream

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/trillian/client/backoff"
)

func rawEntriesStopIndex(start, end int64) (stop int64) {
	stop = start
	if start <= end {
		stop = start + min(end-start+1, LogBatchSize) - 1
	}
	return
}

func (ls *LogStream) getRawEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	next = start
	if start <= end {
		if ls.isTiled() {
			next, wanted = ls.getTileEntries(ctx, start, end, historical, handleFn, gapcounter)
		} else {
			client := ls.headClient
			if historical && ls.tailClient != nil {
				client = ls.tailClient
			}
			next, wanted = ls.getRawEntriesRange(ctx, client, start, end, historical, handleFn, gapcounter)
		}
	}
	return
}

func (ls *LogStream) getRawEntriesSubRange(ctx context.Context, client rawEntriesClient, start, end int64, historical bool) (entries []ct.LeafEntry, err error) {
	for start <= end && err == nil {
		stopIndex := rawEntriesStopIndex(start, end)
		bo := &backoff.Backoff{
			Min:    1 * time.Second,
			Max:    30 * time.Second,
			Factor: 2,
			Jitter: true,
		}
		var resp *ct.GetEntriesResponse
		if err = bo.Retry(ctx, func() (e error) {
			ls.adjustTailLimiter(historical)
			if resp, e = client.GetRawEntries(ctx, start, stopIndex); e != nil {
				if !ls.handleStreamError(e, "GetRawEntries") {
					e = backoff.RetriableError(e.Error())
				}
			}
			return
		}); err == nil {
			if len(resp.Entries) > 0 {
				entries = append(entries, resp.Entries...)
				start += int64(len(resp.Entries))
			} else {
				err = io.ErrNoProgress
			}
		}
	}
	return
}

func (ls *LogStream) getRawEntriesRange(ctx context.Context, client rawEntriesClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	next = start
	stop := false
	processEntries := func(entries []ct.LeafEntry) {
		now := time.Now()
		for i := range entries {
			le := ls.makeLogEntry(start, entries[i], historical)
			ls.seeIndex(start)
			if handleFn(ctx, now, le) {
				wanted = true
			}
			start++
			next = start
			if gapcounter != nil {
				gapcounter.Add(-1)
			}
		}
	}
	applyEntries := func(entries []ct.LeafEntry, requested int64, err error) (short bool, ok bool) {
		if err == nil {
			if len(entries) > 0 {
				processEntries(entries)
			}
			if int64(len(entries)) < requested {
				short = true
			}
			if historical && !wanted {
				stop = true
			}
			ok = true
		} else {
			if gapcounter != nil && ctx.Err() == nil {
				_ = ls.LogError(err, "gap not fillable", "url", ls.URL(), "start", start, "end", end)
				gapcounter.Add(start - (end + 1))
			}
			stop = true
		}
		return
	}
	type rawEntriesRange struct {
		start int64
		end   int64
	}
	type rawEntriesResult struct {
		rng     rawEntriesRange
		entries []ct.LeafEntry
		err     error
	}
	for start <= end && !stop {
		if ctx.Err() == nil {
			rangeStop := false
			requested := min(end-start+1, LogBatchSize)
			if requested > 0 {
				rangeEnd := start + requested - 1
				entries, err := ls.getRawEntriesSubRange(ctx, client, start, rangeEnd, historical)
				short, ok := applyEntries(entries, requested, err)
				if ok && short {
					rangeStop = true
				}
				if err == nil && !stop && !rangeStop {
					entriesRemaining := end - start + 1
					if entriesRemaining > 0 {
						chunkSize := max(1, min(32, int64(len(entries))))
						parallel := max(1, int(min(entriesRemaining, LogBatchSize)/chunkSize))
						ranges := make([]rawEntriesRange, 0, parallel)
						rangeStart := start
						for i := 0; i < parallel && rangeStart <= end; i++ {
							rangeEnd := rangeStart + chunkSize - 1
							if rangeEnd > end {
								rangeEnd = end
							}
							ranges = append(ranges, rawEntriesRange{start: rangeStart, end: rangeEnd})
							rangeStart = rangeEnd + 1
						}
						results := make([]rawEntriesResult, len(ranges))
						var wg sync.WaitGroup
						for i, rng := range ranges {
							wg.Add(1)
							go func(idx int, r rawEntriesRange) {
								defer wg.Done()
								entries, err := ls.getRawEntriesSubRange(ctx, client, r.start, r.end, historical)
								results[idx] = rawEntriesResult{rng: r, entries: entries, err: err}
							}(i, rng)
						}
						wg.Wait()
						processStop := false
						if ctx.Err() == nil {
							for i := range results {
								if !stop && !processStop {
									result := results[i]
									requested := result.rng.end - result.rng.start + 1
									short, ok := applyEntries(result.entries, requested, result.err)
									if !ok || short {
										processStop = true
									}
								}
							}
						} else {
							stop = true
						}
						if !stop && !processStop && ctx.Err() == nil {
							remaining := end - start + 1
							if remaining > 0 {
								tailEntries, tailErr := ls.getRawEntriesSubRange(ctx, client, start, end, historical)
								_, _ = applyEntries(tailEntries, remaining, tailErr)
							}
						}
					}
				}
			} else {
				stop = true
			}
		} else {
			stop = true
		}
	}
	return
}
