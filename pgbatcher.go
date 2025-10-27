package certstream

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const batcherQueueSize = 16 * 1024

func (cdb *PgDB) finishEntry(ctx context.Context, le *LogEntry) {
	if le == nil {
		return
	}
	ch := le.getSendEntryCh()
	if ch == nil {
		return
	}
	select {
	case <-ctx.Done():
	case ch <- le:
	}
}

func isDeadlockError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "40P01"
	}
	return false
}

func (cdb *PgDB) runEntry(ctx context.Context, le *LogEntry) (err error) {
	if le == nil {
		return nil
	}
	defer cdb.finishEntry(ctx, le)

	args := cdb.queueEntry(le)
	if len(args) == 0 {
		return nil
	}

	for attempts := 0; attempts < 2; attempts++ {
		start := time.Now()
		_, err = cdb.Exec(ctx, cdb.stmtNewEntry, args...)
		elapsed := time.Since(start)
		cdb.mu.Lock()
		cdb.newentrycount++
		cdb.newentrytime += elapsed
		cdb.mu.Unlock()
		if err == nil {
			return nil
		}
		if !isDeadlockError(err) || attempts == 1 {
			return err
		}
	}
	return err
}

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, idlecount int) {
	defer func() {
		cdb.Workers.Add(-1)
		wg.Done()
	}()

	cdb.Workers.Add(1)

	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case le, ok := <-cdb.getBatchCh():
			if !ok {
				return
			}
			if cdb.LogError(cdb.runEntry(ctx, le), "worker") != nil {
				return
			}
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
