package certstream

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const batcherQueueSize = 16 * 1024

func (cdb *PgDB) runBatch(ctx context.Context, batch *pgx.Batch) (err error) {
	now := time.Now()
	err = cdb.SendBatch(ctx, batch).Close()
	elapsed := time.Since(now)
	cdb.mu.Lock()
	cdb.newentrycount += int64(len(batch.QueuedQueries))
	cdb.newentrytime += elapsed
	cdb.mu.Unlock()
	return
}

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, idlecount int) {
	defer func() {
		cdb.Workers.Add(-1)
		wg.Done()
	}()

	cdb.Workers.Add(1)
	batch := &pgx.Batch{}

	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case le, ok := <-cdb.getBatchCh():
			if ok && le != nil {
				batch.Queue(cdb.stmtNewEntry, cdb.queueEntry(le)...)
				if len(batch.QueuedQueries) >= BatchSize {
					if cdb.LogError(cdb.runBatch(ctx, batch), "worker@1") != nil {
						return
					}
					batch = &pgx.Batch{}
				}
			}
		default:
			if len(batch.QueuedQueries) > 0 {
				if cdb.LogError(cdb.runBatch(ctx, batch), "worker@2") != nil {
					return
				}
				batch = &pgx.Batch{}
			} else {
				if idlecount > 0 {
					idlecount--
					if idlecount == 0 {
						return
					}
				}
				time.Sleep(time.Millisecond * 100)
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
	defer wg.Done()

	wg.Add(1)
	go cdb.worker(ctx, wg, -1)

	loaded := 0
	ticks := 0
	ticker := time.NewTicker(interval)
	avgentrytimes := make([]time.Duration, time.Second*10/interval)
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

			if cdb.QueueUsage() > 30 {
				loaded++
				if loaded > 10 {
					loaded /= 2
					wg.Add(1)
					go cdb.worker(ctx, wg, 10)
				}
			} else {
				loaded = 0
			}
		}
	}
}
