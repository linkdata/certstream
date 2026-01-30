package certstream

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/crypto/cryptobyte"
)

type tileEntry struct {
	Timestamp      uint64
	IsPrecert      bool
	Certificate    []byte
	Precertificate []byte
}

func parseTileEntry(data []byte) (*tileEntry, error) {
	b := cryptobyte.String(data)
	var timestamp uint64
	if !b.ReadUint64(&timestamp) {
		return nil, errors.New("tile entry missing timestamp")
	}
	var entryType uint16
	if !b.ReadUint16(&entryType) {
		return nil, errors.New("tile entry missing entry type")
	}
	entry := &tileEntry{Timestamp: timestamp}
	switch entryType {
	case 0:
		var cert cryptobyte.String
		if !b.ReadUint24LengthPrefixed(&cert) {
			return nil, errors.New("tile entry missing certificate")
		}
		entry.Certificate = cert
	case 1:
		entry.IsPrecert = true
		if !b.Skip(sha256.Size) {
			return nil, errors.New("tile entry missing issuer key hash")
		}
		var tbs cryptobyte.String
		if !b.ReadUint24LengthPrefixed(&tbs) {
			return nil, errors.New("tile entry missing precert tbs")
		}
		entry.Certificate = tbs
	default:
		return nil, fmt.Errorf("tile entry has unexpected entry type %d", entryType)
	}
	var extensions cryptobyte.String
	if !b.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("tile entry missing extensions")
	}
	if entry.IsPrecert {
		var precert cryptobyte.String
		if !b.ReadUint24LengthPrefixed(&precert) {
			return nil, errors.New("tile entry missing precertificate")
		}
		entry.Precertificate = precert
	}
	var fingerprints cryptobyte.String
	if !b.ReadUint16LengthPrefixed(&fingerprints) {
		return nil, errors.New("tile entry missing chain fingerprints")
	}
	if !b.Empty() {
		return nil, errors.New("tile entry contains trailing data")
	}
	return entry, nil
}

type tileEntryCache struct {
	bundleIndex uint64
	bundle      api.EntryBundle
	ok          bool
}

func (c *tileEntryCache) entryAt(ctx context.Context, client *tileClient, index uint64, logSize uint64) ([]byte, error) {
	bundleIndex := index / layout.EntryBundleWidth
	if !c.ok || c.bundleIndex != bundleIndex {
		bundle, err := client.entryBundle(ctx, bundleIndex, logSize)
		if err != nil {
			return nil, err
		}
		c.bundleIndex = bundleIndex
		c.bundle = bundle
		c.ok = true
	}
	offset := int(index % layout.EntryBundleWidth)
	if offset < 0 || offset >= len(c.bundle.Entries) {
		return nil, fmt.Errorf("tile entry index %d out of bounds", index)
	}
	return c.bundle.Entries[offset], nil
}

func (ls *LogStream) makeTileLogEntry(logindex int64, entry *tileEntry, historical bool) (le *LogEntry) {
	le = &LogEntry{
		LogStream:  ls,
		LogIndex:   logindex,
		Historical: historical,
	}
	if entry != nil {
		le.Seen = time.UnixMilli(int64(entry.Timestamp)).UTC()
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
		if entry.IsPrecert && len(entry.Precertificate) > 0 {
			shasig := sha256.Sum256(entry.Precertificate)
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

func (ls *LogStream) getTileEntries(ctx context.Context, client *tileClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool, next int64, err error) {
	next = start
	if start > end || client == nil {
		return
	}
	var checkpointSize uint64
	if err = ls.backoff.Retry(ctx, func() error {
		ls.adjustTailLimiter(historical)
		checkpoint, _, chkErr := client.checkpoint(ctx)
		if chkErr == nil && checkpoint != nil {
			checkpointSize = checkpoint.Size
			return nil
		}
		if chkErr == nil {
			chkErr = errors.New("checkpoint missing")
		}
		if ls.handleStreamError(chkErr, "Checkpoint") {
			return chkErr
		}
		return wrapLogStreamRetryable(chkErr)
	}); err != nil {
		if ctx.Err() == nil && gapcounter != nil {
			_ = ls.LogError(err, "gap not fillable", "url", ls.URL(), "start", start, "end", end)
			gapcounter.Add(start - (end + 1))
		}
		return
	}
	if checkpointSize == 0 {
		return
	}
	maxIndex := int64(checkpointSize) - 1 //#nosec G115
	if end > maxIndex {
		end = maxIndex
	}
	cache := &tileEntryCache{}
	for start <= end && err == nil {
		logIndex := start
		var entryData []byte
		if err = ls.backoff.Retry(ctx, func() error {
			ls.adjustTailLimiter(historical)
			var fetchErr error
			entryData, fetchErr = cache.entryAt(ctx, client, uint64(logIndex), checkpointSize)
			if fetchErr == nil {
				return nil
			}
			if ls.handleStreamError(fetchErr, "Entries") {
				return fetchErr
			}
			return wrapLogStreamRetryable(fetchErr)
		}); err == nil {
			now := time.Now()
			entry, parseErr := parseTileEntry(entryData)
			le := ls.makeTileLogEntry(logIndex, entry, historical)
			if parseErr != nil {
				le.Err = parseErr
			}
			if handleFn(ctx, now, le) {
				wanted = true
			}
			ls.seeIndex(logIndex)
			start++
			next = start
			if gapcounter != nil {
				gapcounter.Add(-1)
			}
		} else {
			if ctx.Err() == nil {
				_ = ls.LogError(err, "Entries", "url", ls.URL(), "start", start, "end", end)
			}
			if gapcounter != nil {
				gapcounter.Add(start - (end + 1))
			}
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	return
}

// getTileEntriesParallel fetches and processes the logentries in the index range start...end (inclusive) using Config.Concurrency workers.
// The returned next start index can be less than end+1 if an error occured.
// Returns the next start index and 'wanted' set to true if handleFn returned true for any logentry.
func (ls *LogStream) getTileEntriesParallel(ctx context.Context, client *tileClient, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (wanted bool, next int64, err error) {
	type tileEntriesRange struct {
		start int64
		end   int64
	}

	err = ctx.Err()
	next = start

	sleepCtx, sleepCancel := context.WithCancel(ctx)
	workCh := make(chan tileEntriesRange)
	workerCount := min(32, max(1, ls.Concurrency))
	workerSleep := time.Second / time.Duration(workerCount)
	completed := make(map[int64]int64)
	var wg sync.WaitGroup
	var workMu sync.Mutex
	for i := range workerCount {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i > 0 && ls.LogOperator != nil {
				if ls.Status429.Load() > 0 {
					_ = sleep(sleepCtx, workerSleep*time.Duration(i))
				}
			}
			for r := range workCh {
				w, _, e := ls.getTileEntries(ctx, client, r.start, r.end, historical, handleFn, gapcounter)
				workMu.Lock()
				wanted = wanted || w
				if e == nil {
					completed[r.start] = r.end
				advanceNext:
					if end, ok := completed[next]; ok {
						delete(completed, next)
						next = end + 1
						goto advanceNext
					}
				} else {
					err = e
				}
				workMu.Unlock()
			}
		}(i)
	}

	for start <= end && err == nil {
		stopIndex := rawEntriesStopIndex(start, end)
		select {
		case workCh <- tileEntriesRange{start: start, end: stopIndex}:
			start = stopIndex + 1
		case <-ctx.Done():
		}
	}

	close(workCh)
	sleepCancel()
	wg.Wait()
	if err == nil {
		err = ctx.Err()
	}

	return
}
