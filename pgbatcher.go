package certstream

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const insertExpiredEntries = `INSERT /* CERTDB_expired_entries */ INTO CERTDB_entry (seen, logindex, cert, stream)
SELECT marker.seen AT TIME ZONE 'UTC', marker.logindex, 0, marker.stream
FROM unnest($1::timestamptz[], $2::bigint[], $3::integer[]) AS marker(seen, logindex, stream)
ORDER BY marker.stream, marker.logindex
ON CONFLICT (stream, logindex) DO NOTHING;`

func (cdb *PgDB) runBatch(ctx context.Context, queued []*LogEntry) (err error) {
	batchTime := time.Now().UTC()
	var cutoff time.Time
	if cdb.PgCertCutoff != nil {
		cutoff = cdb.PgCertCutoff()
	} else if cdb.PgCertMaxAge > 0 {
		cutoff = batchTime.Add(-cdb.PgCertMaxAge)
	}
	if cutoff.After(batchTime) {
		cutoff = batchTime
	}
	var b []byte
	b = append(b, `[`...)
	var seen []time.Time
	var indexes []int64
	var streams []int32
	for _, le := range queued {
		if le.Certificate != nil && !cutoff.IsZero() && !le.Certificate.NotAfter.After(cutoff) {
			at := le.Seen
			if at.IsZero() {
				at = batchTime
			}
			seen = append(seen, at.UTC().Truncate(time.Second))
			indexes = append(indexes, le.Index())
			streams = append(streams, le.LogStream.Id)
		} else {
			if len(b) > 1 {
				b = append(b, `,`...)
			}
			b = le.appendJSON(b)
		}
	}
	b = append(b, `]`...)
	now := time.Now()
	switch {
	case len(seen) == 0:
		_, err = cdb.Exec(ctx, cdb.funcIngestBatch, string(b))
	case len(b) == 2:
		_, err = cdb.Exec(ctx, cdb.Pfx(insertExpiredEntries), seen, indexes, streams)
	default:
		var batch pgx.Batch
		batch.Queue(cdb.funcIngestBatch, string(b))
		batch.Queue(cdb.Pfx(insertExpiredEntries), seen, indexes, streams)
		err = cdb.SendBatch(ctx, &batch).Close()
	}
	elapsed := time.Since(now)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
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
		tckr := time.NewTicker(1 + (staggerInterval * time.Duration(workerID)))
		stop := false
		var queued []*LogEntry
		for !stop {
			ticked := false
			var flushAck chan struct{}
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
			case le, ok := <-batchCh:
				if !ok {
					stop = true
				} else if le.flushAck != nil {
					flushAck = le.flushAck
					ticked = true
				} else {
					queued = append(queued, le)
				}
			}
			if l := len(queued); l > 0 && (l >= DbIngestBatchSize || ticked || stop) {
				_ = cdb.LogError(cdb.runBatch(ctx, queued), "runBatch")
				if flushAck != nil {
					flushAck <- struct{}{}
					flushAck = nil
				}
				for _, le := range queued {
					if !stop {
						select {
						case <-ctx.Done():
							stop = true
						case cdb.getSendEntryCh() <- le:
						}
					}
				}
				clear(queued)
				queued = queued[:0]
			}
			if flushAck != nil {
				flushAck <- struct{}{}
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
