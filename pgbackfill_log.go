package certstream

import (
	"context"
	"sync"
	"time"
)

type gapCounts struct {
	url           string
	gaps, entries int64
}

func (cdb *PgDB) recordGap(ls *LogStream, g gap) {
	length := (g.end - g.start) + 1
	url := ls.URL()
	cdb.mu.Lock()
	if cdb.gaps == nil {
		cdb.gaps = make(map[int32]gapCounts)
	}
	counts := cdb.gaps[ls.Id]
	counts.url = url
	counts.gaps++
	counts.entries += length
	cdb.gaps[ls.Id] = counts
	cdb.mu.Unlock()
	if length > 1000 {
		cdb.LogInfo("gap", "url", url, "stream", ls.Id, "logindex", g.start, "length", length)
	}
}

func (cdb *PgDB) logGaps() {
	cdb.mu.Lock()
	pending := cdb.gaps
	cdb.gaps = nil
	cdb.mu.Unlock()
	// Counts survive reader replacement or removal until they are reported.
	for id, counts := range pending {
		cdb.LogInfo("gaps", "url", counts.url, "stream", id, "gaps", counts.gaps, "entries", counts.entries)
	}
}

func (cdb *PgDB) reportGaps(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cdb.logGaps()
		}
	}
}
