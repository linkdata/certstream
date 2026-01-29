package certstream

import (
	"context"
	"crypto/sha256"
	"sync/atomic"
	"time"

	"filippo.io/sunlight"
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
	next = start
	if start <= end {
		client := ls.headTile
		if historical && ls.tailTile != nil {
			client = ls.tailTile
		}
		if client != nil {
			var checkpoint sunlight.Checkpoint
			var chkErr error
			chkErr = ls.backoff.Retry(ctx, func() error {
				ls.adjustTailLimiter(historical)
				var err error
				checkpoint, _, err = client.Checkpoint(ctx)
				if err == nil {
					return nil
				}
				if ls.handleStreamError(err, "Checkpoint") {
					return err
				}
				return wrapLogStreamRetryable(err)
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
								entryErr := ls.backoff.Retry(ctx, func() error {
									lastIndex = -1
									ls.adjustTailLimiter(historical)
									now := time.Now()
									for i, entry := range client.Entries(ctx, checkpoint.Tree, start) {
										if i > end {
											break
										}
										le := ls.makeTileLogEntry(i, entry, historical)
										ls.seeIndex(i)
										if handleFn(ctx, now, le) {
											wanted = true
										}
										lastIndex = i
										next = i + 1
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
									return wrapLogStreamRetryable(err)
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
