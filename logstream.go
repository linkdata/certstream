package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/trillian/client/backoff"
)

var BatchSize = 1024

type LogStream struct {
	*LogOperator
	*loglist3.Log
	*client.LogClient
	HttpClient *http.Client
	Err        error        // set if Stopped() returns true
	Count      atomic.Int64 // number of certificates sent to the channel
	MinIndex   atomic.Int64 // atomic: lowest index seen so far, -1 if none seen yet
	MaxIndex   atomic.Int64 // atomic: highest index seen so far, -1 if none seen yet
	LastIndex  atomic.Int64 // atomic: highest index that is available from stream source
	InsideGaps atomic.Int64 // atomic: number of remaining entries inside gaps
	backfilled atomic.Bool  // atomic: nonzero if database backfill called for this stream
	stopped    atomic.Bool  // atomic
	Id         int32        // database ID, if available
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.Log.URL)
}

func NewLogStream(logop *LogOperator, httpClient *http.Client, log *loglist3.Log) (ls *LogStream, err error) {
	var logClient *client.LogClient
	if logClient, err = client.New(log.URL, httpClient, jsonclient.Options{}); err == nil {
		ls = &LogStream{
			LogOperator: logop,
			Log:         log,
			LogClient:   logClient,
			HttpClient:  httpClient,
		}
		ls.MinIndex.Store(-1)
		ls.MaxIndex.Store(-1)
		ls.LastIndex.Store(-1)
	}
	return
}

func (ls *LogStream) Stopped() bool {
	return ls.stopped.Load()
}

func sleep(ctx context.Context, d time.Duration) {
	tmr := time.NewTimer(d)
	defer tmr.Stop()
	select {
	case <-tmr.C:
	case <-ctx.Done():
	}
}

func (ls *LogStream) run(ctx context.Context, wg *sync.WaitGroup, entryCh chan<- *LogEntry) {
	defer wg.Done()
	defer ls.stopped.Store(true)

	end, err := ls.NewLastIndex(ctx)
	start := end
	for err == nil {
		if start < end {
			ls.GetRawEntries(ctx, start, end, func(logindex int64, entry ct.LeafEntry) {
				ls.sendEntry(ctx, entryCh, logindex, entry)
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
	lastIndex = ls.LastIndex.Load()
	err = bo.Retry(ctx, func() error {
		var sth *ct.SignedTreeHead
		sth, err = ls.LogClient.GetSTH(ctx)
		if err == nil {
			newIndex := int64(sth.TreeSize) - 1 //#nosec G115
			if lastIndex < newIndex {
				if lastIndex+int64(BatchSize) < newIndex || time.Since(now) > time.Second*15 {
					lastIndex = newIndex
					ls.LastIndex.Store(lastIndex)
					return nil
				}
			}
			return backoff.RetriableError("STH diff too low")
		}
		return backoff.RetriableError(err.Error())
	})
	return
}

func (ls *LogStream) MakeLogEntry(logindex int64, entry ct.LeafEntry, historical bool) *LogEntry {
	var ctle *ct.LogEntry
	ctrle, leaferr := ct.RawLogEntryFromLeaf(logindex, &entry)
	if leaferr == nil {
		ctle, leaferr = ctrle.ToLogEntry()
	}
	if logindex >= 0 {
		if x := ls.MinIndex.Load(); x > logindex || x == -1 {
			ls.MinIndex.CompareAndSwap(x, logindex)
		}
		if x := ls.MaxIndex.Load(); x < logindex || x == -1 {
			ls.MaxIndex.CompareAndSwap(x, logindex)
		}
	}
	return &LogEntry{
		LogStream:   ls,
		Err:         leaferr,
		RawLogEntry: ctrle,
		LogEntry:    ctle,
		Historical:  historical,
	}
}

func (ls *LogStream) sendEntry(ctx context.Context, entryCh chan<- *LogEntry, logindex int64, entry ct.LeafEntry) {
	le := ls.MakeLogEntry(logindex, entry, false)
	if ls.cdb != nil {
		_ = ls.LogError(ls.cdb.Entry(ctx, le), "cdb.Entry", "url", le.URL, "stream", le.LogStream.Id, "entry", le.Index())
	}
	select {
	case <-ctx.Done():
	case entryCh <- le:
		ls.Count.Add(1)
		ls.LogOperator.Count.Add(1)
	}
}

func (ls *LogStream) handleError(err error) (fatal bool) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	errTxt := err.Error()
	if strings.Contains(errTxt, "context canceled") || strings.Contains(errTxt, "deadline exceeded") {
		return true
	}
	if rspErr, isRspErr := err.(jsonclient.RspError); isRspErr {
		switch rspErr.StatusCode {
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusGatewayTimeout:
			return false
		}
		body := string(rspErr.Body)
		if len(body) > 64 {
			body = body[:64]
		}
		ls.LogError(rspErr, "GetRawEntries", "url", ls.URL, "code", rspErr.StatusCode, "body", body)
		return true
	}
	ls.LogError(err, "GetRawEntries", "url", ls.URL)
	return false
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
			if ls.handleError(err) {
				return
			}
		} else {
			for i := range resp.Entries {
				cb(start, resp.Entries[i])
				start++
			}
		}
	}
}
