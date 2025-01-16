package certstream

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const batcherQueueSize = 16 * 1024

func (cdb *PgDB) runBatch(ctx context.Context, batch *pgx.Batch) (err error) {
	var tx pgx.Tx
	if tx, err = cdb.Begin(ctx); err == nil {
		if err = tx.SendBatch(ctx, batch).Close(); err == nil {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
	}
	return
}

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, idlecount int) {
	// batch := &pgx.Batch{}
	// remain := map[int]struct{}{}
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case le := <-cdb.batchCh:
			/*if cert := le.Cert(); cert != nil {
				var issuer, subject JsonIdentity
				issuer.Fill(&cert.Issuer)
				subject.Fill(&cert.Subject)

			}*/

			for {
				now := time.Now()
				_, err := cdb.Exec(ctx, cdb.stmtNewEntry, cdb.queueEntry(le)...)
				// err := cdb.SendBatch(ctx, batch).Close()
				elapsed := time.Since(now)
				pgerr, ok := err.(*pgconn.PgError)
				if ok && (pgerr.SQLState() == "23505" || pgerr.SQLState() == "40P01") {
					continue
				}
				cdb.LogError(err, "worker")
				cdb.mu.Lock()
				cdb.newentrycount++
				cdb.newentrytime += elapsed
				cdb.mu.Unlock()
				break
			}

		default:
			/*if len(batch.QueuedQueries) > 0 {
				clear(remain)
				for index, qq := range batch.QueuedQueries {
					remain[index] = struct{}{}
					qq.Exec(func(ct pgconn.CommandTag) error {
						delete(remain, index)
						return nil
					})
				}
				now := time.Now()
				err := cdb.SendBatch(ctx, batch).Close()
				elapsed := time.Since(now)
				cdb.mu.Lock()
				cdb.newentrycount += int64(len(batch.QueuedQueries) - len(remain))
				cdb.newentrytime += elapsed
				cdb.mu.Unlock()
				pgerr, ok := err.(*pgconn.PgError)
				if !ok || (pgerr.SQLState() != "23505" && pgerr.SQLState() != "40P01") {
					cdb.LogError(err, "worker")
				}
				newbatch := &pgx.Batch{}
				for index := range remain {
					qq := batch.QueuedQueries[index]
					newbatch.Queue(qq.SQL, qq.Arguments...)
				}
				batch = newbatch
			} else {*/
			if idlecount > 0 {
				idlecount--
				if idlecount == 0 {
					return
				}
			}
			time.Sleep(time.Millisecond * 100)
			//}
		}
	}
}

func (cdb *PgDB) AverageNewEntryTime() (d time.Duration) {
	cdb.mu.Lock()
	d = cdb.newentrytime
	if cdb.newentrycount > 0 {
		d /= time.Duration(cdb.newentrycount)
	}
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
