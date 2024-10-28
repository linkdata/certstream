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
)

type LogStream struct {
	*LogOperator
	*loglist3.Log
	*client.LogClient
	Err       error // set if Stopped() returns true
	Count     int64 // atomic; number of certificates sent to the channel
	LastIndex int64 // atomic: highest index that was available on startup from stream source
	Id        int32 // database ID, if available
	minIndex  int64
	maxIndex  int64
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
			minIndex:    minIndex,
			maxIndex:    maxIndex,
		}
	}
	return
}

func (ls *LogStream) Stopped() bool {
	return atomic.LoadInt32(&ls.stopped) != 0
}

func (ls *LogStream) RunForward(ctx context.Context, entryCh chan<- *LogEntry) {
	defer atomic.AddInt32(&ls.stopped, 1)
	opts := &scanner.FetcherOptions{
		BatchSize:     ls.BatchSize,
		ParallelFetch: ls.ParallelFetch,
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
			opts.StartIndex = min(ls.maxIndex, opts.EndIndex)
			atomic.StoreInt64(&ls.LastIndex, opts.EndIndex)
			err = fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				for n, entry := range eb.Entries {
					var ctle *ct.LogEntry
					index := eb.Start + int64(n)
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
			})
		}
	}
	ls.Err = err
}

func (ls *LogStream) RunBackward(ctx context.Context, entryCh chan<- *LogEntry) {
	defer atomic.AddInt32(&ls.stopped, 1)
	opts := &scanner.FetcherOptions{
		BatchSize:     4096,
		ParallelFetch: 1,
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
			opts.StartIndex = min(ls.minIndex, opts.EndIndex)
			atomic.StoreInt64(&ls.LastIndex, opts.EndIndex)
			err = fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				for n, entry := range eb.Entries {
					var ctle *ct.LogEntry
					index := eb.Start + int64(n)
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
			})
		}
	}
	ls.Err = err
}
