package certstream

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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

var DbBatchSize = 1000
var LogBatchSize = int64(1000)
var MaxErrors = 100
var IdleCloseTime = time.Hour * 24 * 7

type handleEntryFn func(ctx context.Context, now time.Time, logindex int64, entry ct.LeafEntry, historical bool) (wanted bool)

type LogStream struct {
	*LogOperator
	*loglist3.Log
	HeadClient *client.LogClient
	TailClient *client.LogClient
	Count      atomic.Int64 // number of certificates sent to the channel
	MinIndex   atomic.Int64 // atomic: lowest index seen so far, -1 if none seen yet
	MaxIndex   atomic.Int64 // atomic: highest index seen so far, -1 if none seen yet
	LastIndex  atomic.Int64 // atomic: highest index that is available from stream source
	InsideGaps atomic.Int64 // atomic: number of remaining entries inside gaps
	Id         int32        // database ID, if available
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.Log.URL)
}

func sleep(ctx context.Context, d time.Duration) {
	tmr := time.NewTimer(d)
	defer tmr.Stop()
	select {
	case <-tmr.C:
	case <-ctx.Done():
	}
}

func (ls *LogStream) getEndSeen(ctx context.Context, end int64) (seen time.Time) {
	fn := func(ctx context.Context, now time.Time, logindex int64, entry ct.LeafEntry, historical bool) (wanted bool) {
		le := ls.makeLogEntry(logindex, entry, historical)
		if cert := le.Cert(); cert != nil {
			seen = cert.Seen
		}
		return
	}
	ls.GetRawEntries(ctx, end, end, false, fn, nil)
	return
}

func (ls *LogStream) run(ctx context.Context, wg *sync.WaitGroup) {
	var end int64
	var err error
	var wg2 sync.WaitGroup
	defer func() {
		ls.addError(ls, err)
		wg2.Wait()
		ls.removeStream(ls)
		if e, ok := err.(errLogIdle); ok {
			ls.LogInfo("stream stopped", "url", ls.URL, "stream", ls.Id, "idle-since", e.Since)
		} else {
			_ = ls.LogError(err, "stream stopped", "url", ls.URL, "stream", ls.Id)
		}
		wg.Done()
	}()

	end, err = ls.NewLastIndex(ctx)
	if seen := ls.getEndSeen(ctx, end); !seen.IsZero() {
		if time.Since(seen) > IdleCloseTime {
			err = errLogIdle{Since: seen}
			return
		}
	}

	start := end
	if cdb := ls.DB(); cdb != nil {
		if ls.CertStream.Config.TailDialer != nil {
			wg2.Add(1)
			go cdb.backfillStream(ctx, ls, &wg2)
		}
	}

	for err == nil {
		if start < end {
			ls.GetRawEntries(ctx, start, end, false, ls.sendEntry, nil)
			if end-start <= LogBatchSize/2 {
				sleep(ctx, time.Second*time.Duration(10+rand.IntN(10) /*#nosec G404*/))
			}
			start = end
		}
		end, err = ls.NewLastIndex(ctx)
	}
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
				if lastIndex+LogBatchSize < newIndex || time.Since(now) > time.Second*15 {
					lastIndex = newIndex
					ls.LastIndex.Store(lastIndex)
					return nil
				}
			} else {
				if time.Since(now) > IdleCloseTime {
					return errLogIdle{Since: now}
				}
			}
			return backoff.RetriableError("STH diff too low")
		}
		if ls.handleStreamError(err, "GetSTH") {
			return err
		}
		return backoff.RetriableError(err.Error())
	})
	return
}

func (ls *LogStream) seeIndex(logindex int64) {
	if logindex >= 0 {
		if x := ls.MinIndex.Load(); x > logindex || x == -1 {
			ls.MinIndex.CompareAndSwap(x, logindex)
		}
		if x := ls.MaxIndex.Load(); x < logindex || x == -1 {
			ls.MaxIndex.CompareAndSwap(x, logindex)
		}
	}
}

func (ls *LogStream) makeLogEntry(logindex int64, entry ct.LeafEntry, historical bool) *LogEntry {
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
		Historical:  historical,
	}
}

func (ls *LogStream) sendEntry(ctx context.Context, now time.Time, logindex int64, entry ct.LeafEntry, historical bool) (wanted bool) {
	le := ls.makeLogEntry(logindex, entry, historical)
	if cert := le.Cert(); cert != nil {
		ls.seeIndex(logindex)
		wanted = now.Before(cert.NotAfter) || now.Sub(cert.Seen) < time.Hour*24*time.Duration(ls.PgMaxAge)
		if ctx.Err() == nil {
			ls.Count.Add(1)
			ls.LogOperator.Count.Add(1)
			if db := ls.DB(); db != nil {
				db.sendToBatcher(ctx, le)
			} else {
				select {
				case <-ctx.Done():
				case ls.getSendEntryCh() <- le:
				}
			}
		}
	}
	return
}

func (ls *LogStream) handleStreamError(err error, from string) (fatal bool) {
	errTxt := err.Error()
	if errors.Is(err, context.Canceled) || strings.Contains(errTxt, "context canceled") {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errTxt, "deadline exceeded") {
		return false
	}
	rspErr, isRspErr := err.(jsonclient.RspError)
	if isRspErr {
		switch rspErr.StatusCode {
		case http.StatusTooManyRequests,
			http.StatusGatewayTimeout:
			return false
		}
	}
	ls.addError(ls, wrapErr(err, from))
	if isRspErr {
		switch rspErr.StatusCode {
		case http.StatusInternalServerError,
			http.StatusBadGateway:
			return false
		}
	}
	return true
}

func (ls *LogStream) GetRawEntries(ctx context.Context, start, end int64, historical bool, handleFn handleEntryFn, gapcounter *atomic.Int64) (wanted bool) {
	if start > end {
		return false
	}
	client := ls.HeadClient
	if historical && ls.TailClient != nil {
		client = ls.TailClient
	}

	maxparallelism := int64(max(ls.CertStream.Config.GetEntriesParallelism, 1))
	totalEntries := (end - start) + 1
	if historical || maxparallelism == 1 || totalEntries <= LogBatchSize || totalEntries < maxparallelism {
		return ls.getRawEntriesRange(ctx, client, start, end, historical, handleFn, gapcounter)
	}

	type segment struct {
		start int64
		end   int64
	}

	parallelism := min(maxparallelism, totalEntries/LogBatchSize)
	segments := make([]segment, parallelism)
	baseSize := totalEntries / parallelism
	remainder := totalEntries % parallelism
	segStart := start
	for i := range parallelism {
		size := baseSize
		if int64(i) < remainder {
			size++
		}
		segEnd := min(segStart+size-1, end)
		segments[i] = segment{start: segStart, end: segEnd}
		segStart = segEnd + 1
	}

	var anyWanted atomic.Bool
	var wg sync.WaitGroup
	for _, seg := range segments {
		if seg.start <= seg.end {
			wg.Add(1)
			go func(segStart, segEnd int64) {
				defer wg.Done()
				if ls.getRawEntriesRange(ctx, client, segStart, segEnd, historical, handleFn, gapcounter) {
					anyWanted.Store(true)
				}
			}(seg.start, seg.end)
		}
	}
	wg.Wait()
	return anyWanted.Load()
}

func (ls *LogStream) getRawEntriesRange(ctx context.Context, client *client.LogClient, start, end int64, historical bool, handleFn handleEntryFn, gapcounter *atomic.Int64) (wanted bool) {
	for start <= end {
		if ctx.Err() != nil {
			return
		}
		bo := &backoff.Backoff{
			Min:    1 * time.Second,
			Max:    30 * time.Second,
			Factor: 2,
			Jitter: true,
		}
		var resp *ct.GetEntriesResponse
		stop := start + min(LogBatchSize, end-start)
		if err := bo.Retry(ctx, func() error {
			var err error
			resp, err = client.GetRawEntries(ctx, start, stop)
			return err
		}); err != nil {
			if ls.handleStreamError(err, "GetRawEntries") {
				if gapcounter != nil && ctx.Err() == nil {
					_ = ls.LogError(err, "gap not fillable", "url", ls.URL, "start", start, "end", end)
					gapcounter.Add(start - (end + 1))
				}
				return
			}
		} else {
			now := time.Now()
			for i := range resp.Entries {
				if handleFn(ctx, now, start, resp.Entries[i], historical) {
					wanted = true
				}
				start++
				if gapcounter != nil {
					gapcounter.Add(-1)
				}
			}
			if historical && !wanted {
				return
			}
		}
		for historical && ctx.Err() == nil {
			if db := ls.DB(); db != nil {
				if qu := db.QueueUsage(); qu > 40 {
					sleep(ctx, time.Millisecond*time.Duration(qu-40))
					continue
				}
			}
			break
		}
	}
	return
}
