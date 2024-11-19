package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/trillian/client/backoff"
	"github.com/linkdata/bwlimit"
)

var BatchSize = 1024

type LogStream struct {
	*LogOperator
	*loglist3.Log
	*client.LogClient
	HttpClient    *http.Client
	DialContextFn bwlimit.DialContextFn
	Err           error // set if Stopped() returns true
	Count         int64 // atomic: number of certificates sent to the channel
	MinIndex      int64 // atomic: lowest index seen so far, -1 if none seen yet
	MaxIndex      int64 // atomic: highest index seen so far, -1 if none seen yet
	LastIndex     int64 // atomic: highest index that is available from stream source
	Id            int32 // database ID, if available
	Backfilled    int32 // atomic: nonzero if database backfill called for this stream
	stopped       int32 // atomic
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.Log.URL)
}

func NewLogStream(logop *LogOperator, httpClient *http.Client, dc bwlimit.DialContextFn, log *loglist3.Log) (ls *LogStream, err error) {
	var logClient *client.LogClient
	if logClient, err = client.New(log.URL, httpClient, jsonclient.Options{}); err == nil {
		ls = &LogStream{
			LogOperator:   logop,
			Log:           log,
			LogClient:     logClient,
			HttpClient:    httpClient,
			DialContextFn: dc,
			MinIndex:      -1,
			MaxIndex:      -1,
			LastIndex:     -1,
		}
	}
	return
}

func (ls *LogStream) Stopped() bool {
	return atomic.LoadInt32(&ls.stopped) != 0
}

func sleep(ctx context.Context, d time.Duration) {
	tmr := time.NewTimer(d)
	defer tmr.Stop()
	select {
	case <-tmr.C:
	case <-ctx.Done():
	}
}

func (ls *LogStream) Run(ctx context.Context, entryCh chan<- *LogEntry) {
	defer atomic.StoreInt32(&ls.stopped, 1)

	end, err := ls.NewLastIndex(ctx)
	start := end
	for err == nil {
		if start < end {
			ls.GetRawEntries(ctx, start, end, func(logindex int64, entry ct.LeafEntry) {
				ls.SendEntry(entryCh, logindex, entry)
			})
			if end-start <= int64(BatchSize/2) {
				sleep(ctx, time.Second*15)
			}
			start = end
		}
		end, err = ls.NewLastIndex(ctx)
	}
	ls.Err = err
}

func (ls *LogStream) NewLastIndex(ctx context.Context) (lastIndex int64, err error) {
	bo := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    5 * time.Minute,
		Factor: 2,
		Jitter: true,
	}
	now := time.Now()
	lastIndex = atomic.LoadInt64(&ls.LastIndex)
	err = bo.Retry(ctx, func() error {
		var sth *ct.SignedTreeHead
		sth, err = ls.LogClient.GetSTH(ctx)
		if err == nil {
			newIndex := int64(sth.TreeSize) - 1
			if lastIndex < newIndex {
				if lastIndex+int64(BatchSize) < newIndex || time.Since(now) > time.Second*15 {
					lastIndex = newIndex
					atomic.StoreInt64(&ls.LastIndex, lastIndex)
					return nil
				}
			}
			return backoff.RetriableError("STH diff too low")
		}
		return backoff.RetriableError(err.Error())
	})
	return
}

func (ls *LogStream) MakeLogEntry(logindex int64, entry ct.LeafEntry) *LogEntry {
	var ctle *ct.LogEntry
	ctrle, leaferr := ct.RawLogEntryFromLeaf(logindex, &entry)
	if leaferr == nil {
		ctle, leaferr = ctrle.ToLogEntry()
	}
	if logindex >= 0 {
		if x := atomic.LoadInt64(&ls.MinIndex); x > logindex || x == -1 {
			atomic.StoreInt64(&ls.MinIndex, logindex)
		}
		if x := atomic.LoadInt64(&ls.MaxIndex); x < logindex || x == -1 {
			atomic.StoreInt64(&ls.MaxIndex, logindex)
		}
	}
	return &LogEntry{
		LogStream:   ls,
		Err:         leaferr,
		RawLogEntry: ctrle,
		LogEntry:    ctle,
	}
}

func (ls *LogStream) SendEntry(entryCh chan<- *LogEntry, logindex int64, entry ct.LeafEntry) {
	entryCh <- ls.MakeLogEntry(logindex, entry)
	atomic.AddInt64(&ls.Count, 1)
	atomic.AddInt64(&ls.LogOperator.Count, 1)
}

func (ls *LogStream) GetRawEntries(ctx context.Context, start, end int64, cb func(logindex int64, entry ct.LeafEntry)) {
	for start <= end {
		bo := &backoff.Backoff{
			Min:    1 * time.Second,
			Max:    30 * time.Second,
			Factor: 2,
			Jitter: true,
		}
		var resp *ct.GetEntriesResponse
		stop := start + min(int64(BatchSize), end-start)
		if err := bo.Retry(ctx, func() error {
			var err error
			resp, err = ls.LogClient.GetRawEntries(ctx, start, stop)
			return err
		}); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if rspErr, isRspErr := err.(jsonclient.RspError); isRspErr {
				switch rspErr.StatusCode {
				case http.StatusTooManyRequests,
					http.StatusInternalServerError,
					http.StatusBadGateway,
					http.StatusGatewayTimeout:
					continue
				}
			}
			if s := err.Error(); strings.Contains(s, "deadline exceeded") || strings.Contains(s, "context canceled") {
				continue
			}
			ls.LogError(err, "GetRawEntries", "url", ls.URL, "start", start, "stop", stop, "end", end, "last", ls.LastIndex)
		} else {
			for i := range resp.Entries {
				cb(start, resp.Entries[i])
				start++
			}
		}
	}
}
