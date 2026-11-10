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
	"filippo.io/torchwood"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

var (
	DbIngestBatchSize   = 1000 // number of entries to send to ingest at a time
	HistoricalBatchSize = 1000 // number of rows to SELECT when getting historical certificates
	// LogBatchSize sets the classic CT request window.
	//
	// The default is 256. Gap repair uses fixed 256-index requests. Reverse
	// backfill windows align to this setting. Set it to a positive value before
	// calling [Start].
	LogBatchSize  = int64(256)
	MaxErrors     = 100
	IdleCloseTime = time.Hour * 24 * 7
)

type handleLogEntryFn func(ctx context.Context, now time.Time, entry *LogEntry) (wanted bool)

type rawEntriesClient interface {
	GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error)
}

// LogStream tracks one CT log's head, entries, and historical fetches.
type LogStream struct {
	*LogOperator
	Count          atomic.Int64 // atomic: parsed certificates accepted for delivery
	MinIndex       atomic.Int64 // atomic: lowest index seen so far, -1 if none seen yet
	MaxIndex       atomic.Int64 // atomic: highest index seen so far, -1 if none seen yet
	LastIndex      atomic.Int64 // atomic: highest index observed in a CT head, -1 until entries exist
	Backfill       atomic.Int64 // atomic: estimate of discovered gap and reverse-backfill entries left to fetch
	GapScanIndex   atomic.Int64 // atomic: next cold scan index after its last update; may rewind on retry; 0 before the first sweep
	Logger         *slog.Logger // toggled by LogToggle
	Id             int32        // database ID, if available
	gapCh          chan gap     // protected by LogOperator.mu
	tailCheckMax   int64        // protected by LogOperator.mu
	tailCheckValid bool         // protected by LogOperator.mu
	log            *loglist3.Log
	tiledLog       *loglist3.TiledLog
	headClient     *client.LogClient
	tailClient     *client.LogClient
	headTile       *sunlight.Client
	tailTile       *sunlight.Client
	gapTile        *sunlight.Client
	gapReadMu      sync.Mutex
	gapRead        gapTileReadState
	backoff        *logStreamBackoff
	cancel         context.CancelFunc // stops this reader on retirement
	done           chan struct{}      // closed after reader and backfill stop

	gapScanContinuous atomic.Bool
	gapScanWakeOnce   sync.Once
	gapScanWake       chan struct{}
}

// GapScanContinuous reports whether this stream uses continuous gap scanning.
//
// The zero value uses shared gap scan scheduling.
func (ls *LogStream) GapScanContinuous() bool {
	return ls.gapScanContinuous.Load()
}

// SetGapScanContinuous selects continuous gap scanning for this stream.
//
// Continuous scans run without the shared scan permit or database queue limit.
// The setting turns off after a complete sweep through the end fixed when that sweep starts,
// even if some gap fetches fail. Queued gap fetches may continue after it turns off.
// Partial scans and query errors keep it on.
// Changing the setting wakes a sleeping scanner. An in-flight query may run
// until it completes or reaches its timeout.
func (ls *LogStream) SetGapScanContinuous(enabled bool) {
	if ls.gapScanContinuous.Swap(enabled) != enabled {
		select {
		case ls.gapScanWakeCh() <- struct{}{}:
		default:
		}
	}
}

func (ls *LogStream) gapScanWakeCh() chan struct{} {
	ls.gapScanWakeOnce.Do(func() { ls.gapScanWake = make(chan struct{}, 1) })
	return ls.gapScanWake
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

func (ls *LogStream) waitForQueue(ctx context.Context, historical bool) (err error) {
	if historical {
		if db := ls.DB(); db != nil {
			for db.QueueUsage() > 50 && err == nil {
				err = sleep(ctx, 100*time.Millisecond)
			}
		}
	}
	return
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
	var err error
	var wg2 sync.WaitGroup
	defer func() {
		if ls.cancel != nil {
			ls.cancel()
		}
		if !errors.Is(err, context.Canceled) {
			ls.addError(ls, err)
		}
		wg2.Wait()
		ls.removeStream(ls)
		if e, ok := err.(errLogIdle); ok {
			ls.LogInfo("stream stopped", "url", ls.URL(), "stream", ls.Id, "idle-since", e.Since)
		} else {
			_ = ls.LogError(err, "stream stopped", "url", ls.URL(), "stream", ls.Id)
		}
		wg.Done()
		if ls.done != nil {
			close(ls.done)
		}
	}()

	started := false
	for err == nil {
		var end int64
		var cache headPollCache
		end, err = ls.newLastIndex(withHeadPollCache(ctx, &cache))
		if err == nil && end >= 0 && !started {
			if seen := ls.getEndSeen(ctx, end); !seen.IsZero() {
				if time.Since(seen) > IdleCloseTime {
					err = errLogIdle{Since: seen}
					return
				}
			}
			if cdb := ls.DB(); cdb != nil && ls.TailDialer != nil {
				backfillCtx, cancelBackfill := context.WithCancel(ctx)
				defer cancelBackfill()
				wg2.Add(1)
				go cdb.backfillStream(backfillCtx, ls, &wg2)
			}
			wg2.Add(1)
			go ls.readEntries(ctx, end, &wg2)
			started = true
		}
		if err == nil {
			err = sleep(ctx, cache.delay(time.Millisecond*time.Duration(8000+rand.IntN(4000) /*#nosec G404*/)))
		}
	}
}

func (ls *LogStream) readEntries(ctx context.Context, start int64, wg *sync.WaitGroup) {
	defer wg.Done()
	for ctx.Err() == nil {
		wait := time.Second
		end := ls.LastIndex.Load()
		if start <= end {
			if next, _ := ls.getEntries(ctx, start, end, false, ls.sendEntry, nil); next > start {
				start = next
				continue
			}
			wait = 10 * time.Second
		}
		_ = sleep(ctx, wait)
	}
}

func (ls *LogStream) newLastIndex(ctx context.Context) (lastIndex int64, err error) {
	var newIndex int64
	err = ls.backoff.Retry(ctx, func() (callErr error) {
		var errFrom string
		if ls.isTiled() {
			errFrom = "Checkpoint"
			if ls.headTile != nil {
				var checkpoint torchwood.Checkpoint
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
		updateAtomicMax(&ls.LastIndex, newIndex)
		lastIndex = ls.LastIndex.Load()
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
	var raw []byte
	var hasRaw bool
	if ctrle != nil {
		raw = ctrle.Cert.Data
		hasRaw = true
		if tse := ctrle.Leaf.TimestampedEntry; tse != nil {
			ts := int64(tse.Timestamp) //#nosec G115
			le.Seen = time.UnixMilli(ts).UTC()
		}
	} else if leaferr != nil {
		// A malformed extra_data can leave certificate or TBS bytes in leaf_input.
		var leaf ct.MerkleTreeLeaf
		if rest, err := tls.Unmarshal(entry.LeafInput, &leaf); err == nil && len(rest) == 0 {
			if tse := leaf.TimestampedEntry; tse != nil {
				ts := int64(tse.Timestamp) //#nosec G115
				le.Seen = time.UnixMilli(ts).UTC()
				if tse.X509Entry != nil {
					raw = tse.X509Entry.Data
					hasRaw = true
					// X.509 leaf_input has full DER even when extra_data is malformed.
					if cert, certErr := x509.ParseCertificate(raw); !x509.IsFatal(certErr) {
						le.Certificate = cert
					}
				} else if tse.PrecertEntry != nil {
					raw = tse.PrecertEntry.TBSCertificate
					hasRaw = true
				}
			}
		}
	}
	if len(raw) > 0 {
		shasig := sha256.Sum256(raw)
		le.Signature = shasig[:]
	}
	if hasRaw && le.Certificate == nil && le.Err != nil {
		le.rawCert = append([]byte{}, raw...)
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

func (ls *LogStream) prepareEntry(ctx context.Context, now time.Time, le *LogEntry) (wanted, store bool) {
	if le != nil {
		if cert := le.Cert(); cert != nil {
			ls.seeIndex(le.LogIndex)
			wanted = now.Before(cert.NotAfter) || now.Sub(cert.Seen) < time.Hour*24*time.Duration(ls.PgMaxAge)
			if ctx.Err() == nil {
				ls.Count.Add(1)
				ls.LogOperator.Count.Add(1)
				store = true
			}
		} else {
			wanted = true
			err := le.Err
			if err == nil {
				err = os.ErrInvalid
			}
			_ = ls.LogError(err, "sendEntry", "url", ls.URL(), "stream", ls.Id, "logindex", le.LogIndex)
			if le.Err != nil && ctx.Err() == nil {
				store = true
			}
		}
	}
	return
}

func (ls *LogStream) sendEntry(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
	wanted, store := ls.prepareEntry(ctx, now, le)
	if store {
		if db := ls.DB(); db != nil {
			db.sendToBatcher(ctx, le)
		} else if le.Certificate != nil {
			select {
			case <-ctx.Done():
			case ls.getSendEntryCh() <- le:
			}
		}
	}
	return
}

func (ls *LogStream) handleStreamError(err error, from string) (fatal bool) {
	errTxt := err.Error()
	underlyingErr := err
	var rspErr jsonclient.RspError
	// jsonclient.RspError keeps its cause in Err without unwrapping it.
	if errors.As(err, &rspErr) {
		underlyingErr = rspErr.Err
	}
	if errors.Is(err, context.Canceled) || errors.Is(underlyingErr, context.Canceled) || errors.Is(err, os.ErrInvalid) || errors.Is(err, io.ErrNoProgress) || strings.Contains(errTxt, "context canceled") {
		fatal = true
	} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(underlyingErr, context.DeadlineExceeded) || strings.Contains(errTxt, "deadline exceeded") {
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
