package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/trillian/client/backoff"
)

type LogStream struct {
	*LogOperator
	*loglist3.Log
	*client.LogClient
	Err       error // set if Stopped() returns true
	Count     int64 // atomic; number of certificates sent to the channel
	LastIndex int64 // atomic: highest index that is available from stream source
	Id        int32 // database ID, if available
	stopped   int32 // atomic
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
			LastIndex:   -1,
		}
	}
	return
}

func (ls *LogStream) Stopped() bool {
	return atomic.LoadInt32(&ls.stopped) != 0
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
			start = end
		}
		end, err = ls.NewLastIndex(ctx)
	}
	ls.Err = err
}

func (ls *LogStream) NewLastIndex(ctx context.Context) (lastIndex int64, err error) {
	bo := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    60 * time.Second,
		Factor: 2,
		Jitter: true,
	}
	lastIndex = atomic.LoadInt64(&ls.LastIndex)
	err = bo.Retry(ctx, func() error {
		var sth *ct.SignedTreeHead
		sth, err = ls.LogClient.GetSTH(ctx)
		if err == nil {
			newIndex := int64(sth.TreeSize) - 1
			if lastIndex < newIndex {
				lastIndex = newIndex
				atomic.StoreInt64(&ls.LastIndex, lastIndex)
				return nil
			}
			return backoff.RetriableError("STH unchanged")
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
		if err := bo.Retry(ctx, func() error {
			var err error
			resp, err = ls.LogClient.GetRawEntries(ctx, start, start+min(1024, end-start))
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
				case http.StatusTooManyRequests, http.StatusInternalServerError:
					continue
				}
			}
			ls.LogError(err, "GetRawEntries", "url", ls.URL, "start", start, "end", end, "last", ls.LastIndex)
		} else {
			for i := range resp.Entries {
				cb(start, resp.Entries[i])
				start++
			}
		}
	}
}
