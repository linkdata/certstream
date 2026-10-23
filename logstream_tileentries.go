package certstream

import (
	"context"
	"crypto/sha256"
	"sync/atomic"
	"time"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"github.com/google/certificate-transparency-go/x509"
)

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

func (ls *LogStream) getTileEntries(ctx context.Context, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	client := ls.headTile
	if historical && ls.tailTile != nil {
		client = ls.tailTile
	}
	return ls.getTileEntriesWithClient(ctx, client, start, end, historical, handleFn, gapcounter)
}

func (ls *LogStream) getTileEntriesWithClient(ctx context.Context, client *sunlight.Client, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	next = start
	for next <= end {
		entryErr := ls.backoff.Retry(ctx, func() (err error) {
			if err = ls.waitForQueue(ctx, historical); err != nil {
				return
			}
			var checkpoint torchwood.Checkpoint
			if checkpoint, _, err = client.Checkpoint(ctx); err == nil {
				if next >= checkpoint.N {
					return wrapLogStreamRetryable(ErrSTHDiffTooLow)
				}
				processEntry := func(logindex int64, entry *sunlight.LogEntry) {
					le := ls.makeTileLogEntry(logindex, entry, historical)
					ls.seeIndex(logindex)
					if handleFn(ctx, time.Now(), le) {
						wanted = true
					}
					next = logindex + 1
					if gapcounter != nil {
						gapcounter.Add(-1)
					}
				}
				if err = ls.waitForQueue(ctx, historical); err != nil {
					return
				}
				if next == end {
					var entry *sunlight.LogEntry
					if entry, _, err = client.Entry(ctx, checkpoint.Tree, next); err == nil {
						processEntry(next, entry)
					}
				} else {
					for logindex, entry := range client.Entries(ctx, checkpoint.Tree, next) {
						if err = ls.waitForQueue(ctx, historical); err != nil {
							break
						}
						processEntry(logindex, entry)
						if logindex >= end {
							break
						}
					}
					if err == nil {
						err = client.Err()
					}
				}
			}
			if err != nil {
				if !ls.handleStreamError(err, "getTileEntries") {
					err = wrapLogStreamRetryable(err)
				}
			}
			return
		})
		if entryErr != nil {
			if gapcounter != nil && ctx.Err() == nil {
				_ = ls.LogError(entryErr, "gap not fillable", "url", ls.URL(), "start", next, "end", end)
				gapcounter.Add(next - (end + 1))
			}
			break
		}
	}
	return
}
