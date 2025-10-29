package certstream

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func (cdb *PgDB) runBatch(ctx context.Context, queued []*LogEntry) (err error) {
	var b []byte
	b = append(b, `[`...)
	for i, le := range queued {
		if i > 0 {
			b = append(b, `,`...)
		}
		b = le.appendJSON(b)
	}
	b = append(b, `]`...)
	now := time.Now()
	_, err = cdb.Exec(ctx, cdb.funcIngestBatch, string(b))
	elapsed := time.Since(now)
	if err != nil {
		if pe, ok := err.(*pgconn.PgError); ok {
			if pe.SQLState() == "22P02" {
				cdb.LogInfo("generated invalid JSON data", "json", string(b))
			}
		}
	}
	cdb.mu.Lock()
	cdb.newentrycount += int64(len(queued))
	cdb.newentrytime += elapsed
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, workerID int) {
	defer wg.Done()
	if batchCh := cdb.getBatchCh(workerID); batchCh != nil {
		cdb.Workers.Add(1)
		defer cdb.Workers.Add(-1)
		const tickerInterval = time.Second * 10
		staggerInterval := tickerInterval / time.Duration(cdb.workerCount)
		tckr := time.NewTicker(staggerInterval * time.Duration(workerID))
		stop := false
		var queued []*LogEntry
		for !stop {
			ticked := false
			select {
			case <-ctx.Done():
				stop = true
			case <-tckr.C:
				ticked = true
				if staggerInterval != 0 {
					staggerInterval = 0
					tckr.Stop()
					tckr = time.NewTicker(tickerInterval)
					defer tckr.Stop()
				}
			case le := <-batchCh:
				queued = append(queued, le)
			}
			if l := len(queued); l > 0 && (l >= DbBatchSize || ticked || stop) {
				_ = cdb.LogError(cdb.runBatch(ctx, queued), "runBatch")
				for _, le := range queued {
					if !stop {
						if ch := cdb.getSendEntryCh(); ch != nil {
							select {
							case <-ctx.Done():
								stop = true
							case ch <- le:
							}
						}
					}
				}
				clear(queued)
				queued = queued[:0]
			}
		}
	}
}

func (cdb *PgDB) AverageNewEntryTime() (d time.Duration) {
	cdb.mu.Lock()
	d = cdb.avgentrytime
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) runWorkers(ctx context.Context, wg *sync.WaitGroup) {
	const interval = time.Millisecond * 100
	defer func() {
		wg.Done()
	}()

	wg.Add(cdb.workerCount)
	for i := 0; i < cdb.workerCount; i++ {
		go cdb.worker(ctx, wg, i)
	}

	ticks := 0
	ticker := time.NewTicker(interval)
	avgentrytimes := make([]time.Duration, time.Minute/interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cdb.mu.Lock()
			avgentrytime := cdb.newentrytime
			if d := time.Duration(cdb.newentrycount); d > 0 {
				avgentrytime /= d
			}
			cdb.newentrytime = 0
			cdb.newentrycount = 0
			avgentrytimes[ticks] = avgentrytime
			ticks++
			if ticks >= cap(avgentrytimes) {
				ticks = 0
			}
			avgentrytime = 0
			for _, d := range avgentrytimes {
				avgentrytime += d
			}
			cdb.avgentrytime = avgentrytime / time.Duration(cap(avgentrytimes))
			cdb.mu.Unlock()
		}
	}
}
