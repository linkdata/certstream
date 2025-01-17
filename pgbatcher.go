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
	return cdb.LogError(err, "runBatch")
}

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, idlecount int) {
	defer wg.Done()
	batch := &pgx.Batch{}

	for {
		select {
		case <-ctx.Done():
			return
		case le := <-cdb.batchCh:
			batch.Queue(cdb.stmtNewEntry, cdb.queueEntry(le)...)
			if len(batch.QueuedQueries) >= BatchSize {
				cdb.runBatch(ctx, batch)
				batch = &pgx.Batch{}
			}
		default:
			if len(batch.QueuedQueries) > 0 {
				cdb.runBatch(ctx, batch)
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

func (cdb *PgDB) batcher(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go cdb.worker(ctx, wg, -1)
	}

	loaded := 0
	ticks := 0
	ticker := time.NewTicker(time.Millisecond * 100)
	avgentrytimes := make([]time.Duration, 100)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cdb.mu.Lock()
			avgentrytime := cdb.newentrytime
			if cdb.newentrycount > 0 {
				avgentrytime /= time.Duration(cdb.newentrycount)
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

			if cdb.Load() > 30 {
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
