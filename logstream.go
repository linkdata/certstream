package certstream

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/trillian/client/backoff"
)

type LogStream struct {
	*LogOperator
	*loglist3.Log
	*client.LogClient
	Err       error // set if Stopped() returns true
	Count     int64 // atomic; number of certificates sent to the channel
	LastIndex int64 // atomic: highest index that was available on startup from stream source
	MinIndex  int64 // atomic: lowest index we fetched all entries down to
	MaxIndex  int64 // atomic: highest index we fetched all entries up to
	Id        int32 // database ID, if available
	stopped   int32 // atomic
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.Log.URL)
}

func NewLogStream(logop *LogOperator, httpClient *http.Client, minIndex, maxIndex int64, log *loglist3.Log) (ls *LogStream, err error) {
	var logClient *client.LogClient
	if logClient, err = client.New(log.URL, httpClient, jsonclient.Options{}); err == nil {
		if minIndex < 0 {
			minIndex = math.MaxInt64
		}
		if maxIndex < 0 {
			maxIndex = math.MaxInt64
		}
		ls = &LogStream{
			LogOperator: logop,
			Log:         log,
			LogClient:   logClient,
			MinIndex:    minIndex,
			MaxIndex:    maxIndex,
		}
	}
	return
}

func (ls *LogStream) Stopped() bool {
	return atomic.LoadInt32(&ls.stopped) != 0
}

func (ls *LogStream) Run(ctx context.Context, entryCh chan<- *LogEntry) {
	defer atomic.StoreInt32(&ls.stopped, 1)
	opts := &scanner.FetcherOptions{
		BatchSize:     1024,
		ParallelFetch: 1,
		Continuous:    true,
	}
	fetcher := scanner.NewFetcher(ls.LogClient, opts)

	var sth *ct.SignedTreeHead
	var err error
	backoff := time.Second * 2
	for sth == nil && err == nil {
		if sth, err = fetcher.Prepare(ctx); err != nil {
			if rspErr, ok := err.(client.RspError); ok {
				if rspErr.StatusCode == http.StatusTooManyRequests {
					time.Sleep(backoff)
					backoff = min(backoff*2, time.Minute)
					err = nil
				}
			}
		}
	}

	if err == nil {
		if err = ls.VerifySTHSignature(*sth); err == nil {
			ls.MinIndex = min(ls.MinIndex, opts.EndIndex)
			ls.MaxIndex = min(ls.MaxIndex, opts.EndIndex)
			opts.StartIndex = min(ls.MaxIndex, opts.EndIndex)
			atomic.StoreInt64(&ls.LastIndex, opts.EndIndex)

			// maybe run backward from minIndex
			if ls.MinIndex > 0 {
				go ls.RunBackward(ctx, entryCh)
			}

			// run forward from maxIndex
			err = fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				for n, entry := range eb.Entries {
					ls.process(entryCh, eb.Start+int64(n), entry)
				}
				atomic.StoreInt64(&ls.MaxIndex, eb.Start+int64(len(eb.Entries)-1))
			})
		}
	}
	ls.Err = err
}

func (ls *LogStream) process(entryCh chan<- *LogEntry, index int64, entry ct.LeafEntry) {
	var ctle *ct.LogEntry
	ctrle, leaferr := ct.RawLogEntryFromLeaf(index, &entry)
	if leaferr == nil {
		ctle, leaferr = ctrle.ToLogEntry()
	}
	le := &LogEntry{
		LogStream:   ls,
		Err:         leaferr,
		RawLogEntry: ctrle,
		LogEntry:    ctle,
	}
	entryCh <- le
	atomic.AddInt64(&ls.Count, 1)
	atomic.AddInt64(&ls.LogOperator.Count, 1)
}

func (ls *LogStream) RunBackward(ctx context.Context, entryCh chan<- *LogEntry) {
	minIndex := atomic.LoadInt64(&ls.MinIndex)
	for minIndex > 0 && ctx.Err() == nil {
		start := max(0, minIndex-1024)
		entries := make([]ct.LeafEntry, minIndex-start)
		ls.fetchRange(ctx, start, entries)
		for i := len(entries) - 1; i >= 0; i-- {
			ls.process(entryCh, start+int64(i), entries[i])
		}
		minIndex = start
		atomic.StoreInt64(&ls.MinIndex, minIndex)
	}
}

func (ls *LogStream) fetchRange(ctx context.Context, start int64, entries []ct.LeafEntry) {
	pos := start
	end := start + int64(len(entries)-1)
	idx := 0
	for pos <= end && ctx.Err() == nil {
		bo := &backoff.Backoff{
			Min:    1 * time.Second,
			Max:    30 * time.Second,
			Factor: 2,
			Jitter: true,
		}

		var resp *ct.GetEntriesResponse
		if err := bo.Retry(ctx, func() error {
			var err error
			resp, err = ls.LogClient.GetRawEntries(ctx, pos, end)
			return err
		}); err != nil {
			if rspErr, isRspErr := err.(jsonclient.RspError); !isRspErr || rspErr.StatusCode != http.StatusTooManyRequests {
				ls.LogError(err, "GetRawEntries", "url", ls.URL, "pos", pos, "end", end)
			}
			continue
		}
		for i := range resp.Entries {
			entries[idx+i] = resp.Entries[i]
		}
		idx += len(resp.Entries)
		pos += int64(len(resp.Entries))
	}
}
