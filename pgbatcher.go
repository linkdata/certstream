package certstream

import (
	"context"
	"sync"
	"time"
)

const batcherQueueSize = 16 * 1024

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, idlecount int) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case le := <-cdb.batchCh:
			_, err := cdb.Exec(ctx, cdb.procNewEntry, cdb.queueEntry(le)...)
			cdb.LogError(err, "worker")
		default:
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

func (cdb *PgDB) batcher(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go cdb.worker(ctx, wg, -1)
	}

	loaded := 0
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
