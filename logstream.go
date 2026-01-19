package certstream

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
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
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/client/backoff"
)

var DbBatchSize = 100
var LogBatchSize = int64(1000)
var MaxErrors = 100
var IdleCloseTime = time.Hour * 24 * 7

type handleLogEntryFn func(ctx context.Context, now time.Time, entry *LogEntry) (wanted bool)

type LogStream struct {
	*LogOperator
	Count      atomic.Int64 // number of certificates sent to the channel
	MinIndex   atomic.Int64 // atomic: lowest index seen so far, -1 if none seen yet
	MaxIndex   atomic.Int64 // atomic: highest index seen so far, -1 if none seen yet
	LastIndex  atomic.Int64 // atomic: highest index that is available from stream source
	InsideGaps atomic.Int64 // atomic: number of remaining entries inside gaps
	Id         int32        // database ID, if available
	gapCh      chan gap     // protected by LogOperator.mu
	log        *loglist3.Log
	tiledLog   *loglist3.TiledLog
	headClient *client.LogClient
	tailClient *client.LogClient
	headTile   *sunlight.Client
	tailTile   *sunlight.Client
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

func sleep(ctx context.Context, d time.Duration) {
	tmr := time.NewTimer(d)
	defer tmr.Stop()
	select {
	case <-tmr.C:
	case <-ctx.Done():
	}
}

func (ls *LogStream) getEndSeen(ctx context.Context, end int64) (seen time.Time) {
	fn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		if cert := le.Cert(); cert != nil {
			seen = cert.Seen
		}
		return
	}
	ls.getRawEntries(ctx, end, end, false, fn, nil)
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
		if start < end {
			ls.getRawEntries(ctx, start, end, false, ls.sendEntry, nil)
			if end-start <= LogBatchSize/2 {
				sleep(ctx, time.Second*time.Duration(10+rand.IntN(10) /*#nosec G404*/))
			}
			start = end
		}
		end, err = ls.newLastIndex(ctx)
	}
}

func (ls *LogStream) newLastIndex(ctx context.Context) (lastIndex int64, err error) {
	bo := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    5 * time.Minute,
		Factor: 2,
		Jitter: true,
	}
	now := time.Now()
	lastIndex = ls.LastIndex.Load()
	err = bo.Retry(ctx, func() error {
		var newIndex int64
		var errFrom string
		if ls.isTiled() {
			errFrom = "Checkpoint"
			if ls.headTile != nil {
				var checkpoint sunlight.Checkpoint
				checkpoint, _, err = ls.headTile.Checkpoint(ctx)
				if err == nil {
					newIndex = checkpoint.N - 1
				}
			} else {
				err = ErrSunlightClientMissing
			}
		} else {
			errFrom = "GetSTH"
			var sth *ct.SignedTreeHead
			sth, err = ls.headClient.GetSTH(ctx)
			if err == nil {
				newIndex = int64(sth.TreeSize) - 1 //#nosec G115
			}
		}
		if err == nil {
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
		if ls.handleStreamError(err, errFrom) {
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

func (ls *LogStream) makeTileLogEntry(logindex int64, entry *sunlight.LogEntry, historical bool) (le *LogEntry) {
	le = &LogEntry{
		LogStream:  ls,
		LogIndex:   logindex,
		Historical: historical,
	}
	if entry != nil {
		le.Seen = time.UnixMilli(entry.Timestamp).UTC()
		if entry.IsPrecert {
			le.PreCert = true
		}
		var cert *x509.Certificate
		var certErr error
		if entry.IsPrecert {
			cert, certErr = x509.ParseTBSCertificate(entry.Certificate)
		} else {
			cert, certErr = x509.ParseCertificate(entry.Certificate)
		}
		if certErr != nil {
			le.Err = certErr
		}
		le.Certificate = cert
		if entry.IsPrecert && len(entry.PreCertificate) > 0 {
			shasig := sha256.Sum256(entry.PreCertificate)
			le.Signature = shasig[:]
		} else if len(entry.Certificate) > 0 {
			shasig := sha256.Sum256(entry.Certificate)
			le.Signature = shasig[:]
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
	return
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
		}
	}
	return
}

func (ls *LogStream) handleStreamError(err error, from string) (fatal bool) {
	errTxt := err.Error()
	if errors.Is(err, context.Canceled) || strings.Contains(errTxt, "context canceled") {
		fatal = true
	} else if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errTxt, "deadline exceeded") {
		fatal = false
	} else {
		var statusCode int
		var hasStatus bool
		statusCode, hasStatus = statusCodeFromError(err)
		fatal = true
		if hasStatus {
			switch statusCode {
			case http.StatusTooManyRequests,
				http.StatusGatewayTimeout,
				http.StatusNotFound:
				fatal = false
			}
		}
		if fatal {
			ls.addError(ls, wrapErr(err, from))
			if hasStatus {
				switch statusCode {
				case http.StatusInternalServerError,
					http.StatusBadGateway:
					fatal = false
				}
			}
		}
	}
	return
}

func statusCodeFromError(err error) (code int, ok bool) {
	if err != nil {
		if rspErr, isRspErr := err.(jsonclient.RspError); isRspErr {
			code = rspErr.StatusCode
			ok = true
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
					var convErr error
					if code, convErr = strconv.Atoi(msg[start:end]); convErr == nil {
						ok = true
					}
				}
			}
		}
	}
	return
}

func (ls *LogStream) getRawEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool) {
	if start <= end {
		if ls.isTiled() {
			wanted = ls.getTileEntries(ctx, start, end, historical, handleFn, gapcounter)
		} else {
			client := ls.headClient
			if historical && ls.tailClient != nil {
				client = ls.tailClient
			}

			maxparallelism := int64(max(ls.CertStream.Config.GetEntriesParallelism, 1))
			totalEntries := (end - start) + 1
			if historical || maxparallelism == 1 || totalEntries <= LogBatchSize || totalEntries < maxparallelism {
				wanted = ls.getRawEntriesRange(ctx, client, start, end, historical, handleFn, gapcounter)
			} else {
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
				wanted = anyWanted.Load()
			}
		}
	}
	return
}

func (ls *LogStream) getRawEntriesRange(ctx context.Context, client *client.LogClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool) {
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
			ls.adjustTailLimiter(historical)
			var err error
			resp, err = client.GetRawEntries(ctx, start, stop)
			return err
		}); err != nil {
			if ls.handleStreamError(err, "GetRawEntries") {
				if gapcounter != nil && ctx.Err() == nil {
					_ = ls.LogError(err, "gap not fillable", "url", ls.URL(), "start", start, "end", end)
					gapcounter.Add(start - (end + 1))
				}
				return
			}
		} else {
			now := time.Now()
			for i := range resp.Entries {
				le := ls.makeLogEntry(start, resp.Entries[i], historical)
				if handleFn(ctx, now, le) {
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
	}
	return
}

func (ls *LogStream) getTileEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool) {
	if start <= end {
		client := ls.headTile
		if historical && ls.tailTile != nil {
			client = ls.tailTile
		}
		if client != nil {
			var checkpoint sunlight.Checkpoint
			bo := &backoff.Backoff{
				Min:    1 * time.Second,
				Max:    30 * time.Second,
				Factor: 2,
				Jitter: true,
			}
			var chkErr error
			chkErr = bo.Retry(ctx, func() error {
				ls.adjustTailLimiter(historical)
				var err error
				checkpoint, _, err = client.Checkpoint(ctx)
				if err == nil {
					return nil
				}
				if ls.handleStreamError(err, "Checkpoint") {
					return err
				}
				return backoff.RetriableError(err.Error())
			})
			if chkErr == nil {
				if checkpoint.N > 0 {
					maxIndex := checkpoint.N - 1
					if end > maxIndex {
						end = maxIndex
					}
					if start <= end {
						for start <= end {
							if ctx.Err() == nil {
								lastIndex := int64(-1)
								entryBo := &backoff.Backoff{
									Min:    1 * time.Second,
									Max:    30 * time.Second,
									Factor: 2,
									Jitter: true,
								}
								entryErr := entryBo.Retry(ctx, func() error {
									lastIndex = -1
									ls.adjustTailLimiter(historical)
									now := time.Now()
									for i, entry := range client.Entries(ctx, checkpoint.Tree, start) {
										if i > end {
											break
										}
										le := ls.makeTileLogEntry(i, entry, historical)
										if handleFn(ctx, now, le) {
											wanted = true
										}
										lastIndex = i
										if gapcounter != nil {
											gapcounter.Add(-1)
										}
									}
									err := client.Err()
									if err == nil {
										return nil
									}
									if ls.handleStreamError(err, "Entries") {
										return err
									}
									return backoff.RetriableError(err.Error())
								})
								if entryErr == nil {
									if lastIndex >= start {
										start = lastIndex + 1
									} else {
										start = end + 1
									}
								} else if gapcounter != nil && ctx.Err() == nil {
									if lastIndex >= start {
										start = lastIndex + 1
									}
									_ = ls.LogError(entryErr, "gap not fillable", "url", ls.URL(), "start", start, "end", end)
									gapcounter.Add(start - (end + 1))
									start = end + 1
								} else {
									start = end + 1
								}
							} else {
								start = end + 1
							}
						}
					}
				}
			} else if gapcounter != nil && ctx.Err() == nil {
				_ = ls.LogError(chkErr, "gap not fillable", "url", ls.URL(), "start", start, "end", end)
				gapcounter.Add(start - (end + 1))
			}
		}
	}
	return
}
