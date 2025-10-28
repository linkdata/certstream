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

func (cdb *PgDB) worker(ctx context.Context, wg *sync.WaitGroup, idlecount int) {
	cdb.Workers.Add(1)
	defer func() {
		cdb.Workers.Add(-1)
		wg.Done()
	}()
	var queued []*LogEntry
	for idlecount != 0 {
		var isIdle bool
		select {
		case <-ctx.Done():
			idlecount = 0
		case le, ok := <-cdb.getBatchCh():
			if ok {
				queued = append(queued, le)
			} else {
				idlecount = 0
			}
		default:
			isIdle = true
		}
		if l := len(queued); l > 0 && (l >= BatchSize || isIdle || idlecount == 0) {
			if cdb.LogError(cdb.runBatch(ctx, queued), "runBatch") != nil {
				idlecount = 0
			} else {
				for _, le := range queued {
					select {
					case <-ctx.Done():
						idlecount = 0
					case cdb.getSendEntryCh() <- le:
					}
				}
			}
			clear(queued)
			queued = queued[:0]
		}
		if isIdle {
			if idlecount > 0 {
				idlecount--
			}
			if idlecount != 0 {
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
				if cdb.Workers.Load() < 32 {
					loaded++
					if loaded > 10 {
						loaded /= 2
						wg.Add(1)
						go cdb.worker(ctx, wg, 10)
					}
				}
			} else {
				loaded = 0
			}
		}
	}
}
