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
	Err        error // set if Stopped() returns true
	Count      int64 // atomic; number of certificates sent to the channel
	Index      int64 // atomic; highest index sent to the channel
	EndIndex   int64 // atomic: highest index that was available on startup
	startIndex int64
	stopped    int32 // atomic
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.Log.URL)
}

func NewLogStream(logop *LogOperator, httpClient *http.Client, startIndex int64, log *loglist3.Log) (ls *LogStream, err error) {
	var logClient *client.LogClient
	if logClient, err = client.New(log.URL, httpClient, jsonclient.Options{}); err == nil {
		if startIndex < 0 {
			startIndex = math.MaxInt64
		}
		ls = &LogStream{
			LogOperator: logop,
			Log:         log,
			LogClient:   logClient,
			startIndex:  startIndex,
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
			opts.StartIndex = min(ls.startIndex, opts.EndIndex)
			atomic.StoreInt64(&ls.EndIndex, opts.EndIndex)
			err = fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				for n, entry := range eb.Entries {
					var le *ct.LogEntry
					index := eb.Start + int64(n)
					rle, leaferr := ct.RawLogEntryFromLeaf(index, &entry)
					if leaferr == nil {
						le, leaferr = rle.ToLogEntry()
					}
					entryCh <- &LogEntry{
						LogStream:   ls,
						Err:         leaferr,
						RawLogEntry: rle,
						LogEntry:    le,
					}
					atomic.AddInt64(&ls.Count, 1)
					atomic.AddInt64(&ls.LogOperator.Count, 1)
					if index > atomic.LoadInt64(&ls.Index) {
						atomic.StoreInt64(&ls.Index, index)
					}
				}
			})
		}
	}
	ls.Err = err
}
