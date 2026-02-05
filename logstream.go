package certstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/sunlight"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
)

var DbIngestBatchSize = 1000   // number of entries to send to ingest at a time
var HistoricalBatchSize = 1000 // number of rows to SELECT when getting historical certificates
var LogBatchSize = int64(1024)
var MaxErrors = 100
var IdleCloseTime = time.Hour * 24 * 7

type handleLogEntryFn func(ctx context.Context, now time.Time, entry *LogEntry) (wanted bool)

type rawEntriesClient interface {
	GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error)
}

type LogStream struct {
	*LogOperator
	Count      atomic.Int64 // number of certificates sent to the channel
	MinIndex   atomic.Int64 // atomic: lowest index seen so far, -1 if none seen yet
	MaxIndex   atomic.Int64 // atomic: highest index seen so far, -1 if none seen yet
	LastIndex  atomic.Int64 // atomic: highest index that is available from stream source
	Backfill   atomic.Int64 // atomic: number of remaining entries to backfill until we reach head
	LogToggle  atomic.Bool
	Logger     *slog.Logger // toggled by LogToggle
	Id         int32        // database ID, if available
	gapCh      chan gap     // protected by LogOperator.mu
	log        *loglist3.Log
	tiledLog   *loglist3.TiledLog
	headClient *client.LogClient
	tailClient *client.LogClient
	headTile   *sunlight.Client
	tailTile   *sunlight.Client
	backoff    *logStreamBackoff
}

func (ls *LogStream) HTTPCalls() int64 {
	return GetHTTPCalls(ls.URL())
}

func (ls *LogStream) URL() string {
	if ls.log != nil {
		return ls.log.URL
	}
	if ls.tiledLog != nil {
		return ls.tiledLog.MonitoringURL
	}
	return ""
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.URL())
}

func (ls *LogStream) logInfo() any {
	if ls != nil {
		if ls.log != nil {
			return ls.log
		}
		if ls.tiledLog != nil {
			return ls.tiledLog
		}
	}
	return nil
}

func (ls *LogStream) isTiled() bool {
	return ls != nil && ls.tiledLog != nil
}

func (ls *LogStream) adjustTailLimiter(historical bool) {
	if historical {
		if db := ls.DB(); db != nil {
			if qu := db.QueueUsage(); qu > 50 {
				readLimit := int64(1) // 1 byte / sec
				if ls.tailLimiter != nil {
					// set rate limit according to queue size
					scaleFactor := int64(50 - (qu - 50))
					readLimit = ls.tailLimiter.Reads.Limit.Load() * scaleFactor / 50
				}
				ls.subLimiter.Reads.Limit.Store(readLimit)
			} else {
				ls.subLimiter.Reads.Limit.Store(0)
			}
		}
	}
}

func (ls *LogStream) getGapCh() (ch chan gap) {
	ls.mu.Lock()
	ch = ls.gapCh
	ls.mu.Unlock()
	return
}

func sleep(ctx context.Context, d time.Duration) (err error) {
	tmr := time.NewTimer(d)
	defer tmr.Stop()
	select {
	case <-tmr.C:
	case <-ctx.Done():
		err = ctx.Err()
	}
	return
}

func (ls *LogStream) getEndSeen(ctx context.Context, end int64) (seen time.Time) {
	fn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		if cert := le.Cert(); cert != nil {
			seen = cert.Seen
		}
		return
	}
	ls.getEntries(ctx, end, end, false, fn, nil)
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
			ls.LogInfo("stream stopped", "url", ls.URL(), "stream", ls.Id, "idle-since", e.Since)
		} else {
			_ = ls.LogError(err, "stream stopped", "url", ls.URL(), "stream", ls.Id)
		}
		wg.Done()
	}()

	end, err = ls.newLastIndex(ctx)
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
		if start <= end {
			startBefore := start
			start, _ = ls.getEntries(ctx, start, end, false, ls.sendEntry, nil)
			if end-startBefore <= LogBatchSize/2 {
				_ = sleep(ctx, time.Second*time.Duration(10+rand.IntN(10) /*#nosec G404*/))
			}
		}
		end, err = ls.newLastIndex(ctx)
	}
}

func (ls *LogStream) newLastIndex(ctx context.Context) (lastIndex int64, err error) {
	started := time.Now()
	var newIndex int64
	lastIndex = ls.LastIndex.Load()
	for err == nil {
		err = ls.backoff.Retry(ctx, func() (callErr error) {
			var errFrom string
			if ls.isTiled() {
				errFrom = "Checkpoint"
				if ls.headTile != nil {
					var checkpoint sunlight.Checkpoint
					checkpoint, _, callErr = ls.headTile.Checkpoint(ctx)
					if callErr == nil {
						newIndex = checkpoint.N - 1
					}
				} else {
					callErr = ErrSunlightClientMissing
				}
			} else {
				errFrom = "GetSTH"
				var sth *ct.SignedTreeHead
				sth, callErr = ls.headClient.GetSTH(ctx)
				if callErr == nil {
					newIndex = int64(sth.TreeSize) - 1 //#nosec G115
				}
			}
			if callErr != nil {
				if ls.handleStreamError(callErr, errFrom) {
					// keep callErr as-is
				} else {
					callErr = wrapLogStreamRetryable(callErr)
				}
			}
			return
		})
		if err == nil {
			if lastIndex < newIndex && (lastIndex+LogBatchSize < newIndex || time.Since(started) > time.Minute) {
				lastIndex = newIndex
				ls.LastIndex.Store(lastIndex)
				return
			}
			err = sleep(ctx, time.Millisecond*time.Duration(8000+rand.IntN(4000)))
		}
	}
	return
}

func (ls *LogStream) seeIndex(logindex int64) {
	if logindex >= 0 {
		updateAtomicMin(&ls.MinIndex, logindex)
		updateAtomicMax(&ls.MaxIndex, logindex)
	}
}

func (ls *LogStream) makeLogEntry(logindex int64, entry ct.LeafEntry, historical bool) *LogEntry {
	ctrle, leaferr := ct.RawLogEntryFromLeaf(logindex, &entry)
	var ctle *ct.LogEntry
	if leaferr == nil {
		ctle, leaferr = ctrle.ToLogEntry()
	}
	le := &LogEntry{
		LogStream:  ls,
		Err:        leaferr,
		LogIndex:   logindex,
		Historical: historical,
	}
	if ctle != nil {
		if ctle.X509Cert != nil {
			le.Certificate = ctle.X509Cert
		} else if ctle.Precert != nil {
			le.PreCert = true
			le.Certificate = ctle.Precert.TBSCertificate
		}
	}
	if ctrle != nil {
		if len(ctrle.Cert.Data) > 0 {
			shasig := sha256.Sum256(ctrle.Cert.Data)
			le.Signature = shasig[:]
		}
		if tse := ctrle.Leaf.TimestampedEntry; tse != nil {
			ts := int64(tse.Timestamp) //#nosec G115
			le.Seen = time.UnixMilli(ts).UTC()
		}
	}
	if len(le.Signature) == 0 && le.Certificate != nil {
		if raw := le.Certificate.Raw; len(raw) > 0 {
			shasig := sha256.Sum256(raw)
			le.Signature = shasig[:]
		} else if raw := le.Certificate.RawTBSCertificate; len(raw) > 0 {
			shasig := sha256.Sum256(raw)
			le.Signature = shasig[:]
		}
	}
	return le
}

func (ls *LogStream) sendEntry(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
	if le != nil {
		if cert := le.Cert(); cert != nil {
			ls.seeIndex(le.LogIndex)
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
		} else {
			wanted = true
			err := le.Err
			if err == nil {
				err = os.ErrInvalid
			}
			ls.LogError(err, "sendEntry", "url", ls.URL(), "stream", ls.Id, "logindex", le.LogIndex)
		}
	}
	return
}

func (ls *LogStream) handleStreamError(err error, from string) (fatal bool) {
	errTxt := err.Error()
	if errors.Is(err, context.Canceled) || errors.Is(err, os.ErrInvalid) || errors.Is(err, io.ErrNoProgress) || strings.Contains(errTxt, "context canceled") {
		fatal = true
	} else if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errTxt, "deadline exceeded") {
		fatal = false
	} else {
		statusCode := ls.statusCodeFromError(err)
		switch statusCode {
		default:
			if ls.addError(ls, wrapErr(err, from)) >= MaxErrors {
				fatal = true
			}
			fallthrough
		case 530: // https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-530/
			fallthrough
		case http.StatusTooManyRequests, http.StatusGatewayTimeout, http.StatusNotFound, http.StatusBadRequest, http.StatusConflict:
			if ls.LogToggle.Load() && ls.Logger != nil {
				ls.Logger.Error(from, "url", ls.URL(), "error", err)
			}
			ls.addStatus(statusCode)
		}
	}
	return
}

func (ls *LogStream) statusCodeFromError(err error) (code int) {
	if err != nil {
		if rspErr, isRspErr := err.(jsonclient.RspError); isRspErr {
			if code = rspErr.StatusCode; code >= 500 {
				// https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/
				if after, found := bytes.CutPrefix(bytes.TrimSpace(rspErr.Body), []byte("error code:")); found {
					if n, err := strconv.Atoi(string(bytes.TrimSpace(after))); err == nil {
						if n >= 1000 {
							code = n
						}
					}
				}
				if code < 1000 {
					ls.LogInfo("code500+", "url", ls.URL(), "stream", ls.Id, "code", code, "body", string(rspErr.Body))
				}
			}
		} else {
			msg := err.Error()
			idx := strings.LastIndex(msg, "status code ")
			if idx >= 0 {
				start := idx + len("status code ")
				end := start
				for end < len(msg) {
					if msg[end] < '0' || msg[end] > '9' {
						break
					}
					end++
				}
				if end > start {
					code, _ = strconv.Atoi(msg[start:end])
				}
			}
		}
	}
	return
}

func (ls *LogStream) getEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	next = start
	if start <= end {
		if ls.isTiled() {
			next, wanted = ls.getTileEntries(ctx, start, end, historical, handleFn, gapcounter)
		} else {
			var fn func(ctx context.Context, client rawEntriesClient, start int64, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool, next int64, err error)
			client := ls.headClient
			fn = ls.getRawEntriesParallel
			if historical {
				fn = ls.getRawEntries
				if ls.tailClient != nil {
					client = ls.tailClient
				}
			}
			wanted, next, _ = fn(ctx, client, start, end, historical, handleFn, gapcounter)
		}
	}
	return
}
