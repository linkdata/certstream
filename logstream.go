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
	HeadClient *client.LogClient
	TailClient *client.LogClient
	Err        error        // set if Stopped() returns true
	Count      atomic.Int64 // number of certificates sent to the channel
	MinIndex   atomic.Int64 // atomic: lowest index seen so far, -1 if none seen yet
	MaxIndex   atomic.Int64 // atomic: highest index seen so far, -1 if none seen yet
	LastIndex  atomic.Int64 // atomic: highest index that is available from stream source
	InsideGaps atomic.Int64 // atomic: number of remaining entries inside gaps
	stopped    atomic.Bool  // atomic
	Id         int32        // database ID, if available
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.Log.URL)
}

func newLogStream(ctx context.Context, logop *LogOperator, headClient, tailClient *http.Client, log *loglist3.Log) {
	if logop != nil {
		var ls *LogStream
		headLogClient, err := client.New(log.URL, headClient, jsonclient.Options{})
		if err == nil {
			var tailLogClient *client.LogClient
			if tailClient != nil {
				tailLogClient, err = client.New(log.URL, tailClient, jsonclient.Options{})
			}
			if err == nil {
				ls = &LogStream{
					LogOperator: logop,
					Log:         log,
					HeadClient:  headLogClient,
					TailClient:  tailLogClient,
				}
				ls.MinIndex.Store(-1)
				ls.MaxIndex.Store(-1)
				ls.LastIndex.Store(-1)
				if logop.DB != nil {
					err = logop.DB.Stream(ctx, ls)
				}
			}
		}
		if logop.LogError(err, "newLogStream", "url", log.URL) == nil {
			logop.Streams = append(logop.Streams, ls)
		}
	}
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

func (ls *LogStream) run(ctx context.Context, wg *sync.WaitGroup) {
	defer func() {
		_ = ls.LogError(ls.Err, "stream stopped", "url", ls.URL, "stream", ls.Id)
		ls.stopped.Store(true)
		wg.Done()
	}()

	end, err := ls.NewLastIndex(ctx)
	start := end
	if cdb := ls.DB; cdb != nil {
		if ls.CertStream.Config.TailDialer != nil {
			wg.Add(1)
			go cdb.backfillStream(ctx, ls, wg)
		}
	}
	for err == nil {
		if start < end {
			ls.GetRawEntries(ctx, start, end, false, nil)
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
		sth, err = ls.HeadClient.GetSTH(ctx)
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

func (ls *LogStream) makeLogEntry(logindex int64, entry ct.LeafEntry, historical bool) *LogEntry {
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

func (ls *LogStream) sendEntry(ctx context.Context, logindex int64, entry ct.LeafEntry, historical bool) {
	le := ls.makeLogEntry(logindex, entry, historical)
	if ls.DB != nil {
		ls.DB.Send(ctx, le)
	}
	select {
	case <-ctx.Done():
	case ls.sendEntryCh <- le:
		ls.Count.Add(1)
		ls.LogOperator.Count.Add(1)
	}
}

func (ls *LogStream) handleError(err error) (fatal bool) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	errTxt := err.Error()
	if strings.Contains(errTxt, "context canceled") {
		return true
	}
	args := []any{"url", ls.URL, "stream", ls.Id}
	if rspErr, isRspErr := err.(jsonclient.RspError); isRspErr {
		switch rspErr.StatusCode {
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusGatewayTimeout:
			return false
		}
		if strings.Contains(errTxt, "deadline exceeded") {
			return false
		}
		b := rspErr.Body
		if len(b) > 64 {
			b = b[:64]
		}
		args = append(args, "code", rspErr.StatusCode, "body", string(b))
		err = rspErr
		fatal = true
	}
	ls.LogError(err, "GetRawEntries", args...)
	return
}

func (ls *LogStream) GetRawEntries(ctx context.Context, start, end int64, historical bool, gapcounter *atomic.Int64) {
	client := ls.HeadClient
	if historical && ls.TailClient != nil {
		client = ls.TailClient
	}
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
			resp, err = client.GetRawEntries(ctx, start, stop)
			return err
		}); err != nil {
			if ls.handleError(err) {
				return
			}
		} else {
			for i := range resp.Entries {
				ls.sendEntry(ctx, start, resp.Entries[i], historical)
				start++
				if gapcounter != nil {
					gapcounter.Add(-1)
				}
			}
		}
	}
}
