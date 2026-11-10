package certstream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const insertSkippedEntries = `INSERT /* CERTDB_skipped_entries */ INTO CERTDB_entry (seen, logindex, cert, stream)
SELECT marker.seen AT TIME ZONE 'UTC', marker.logindex, 0, marker.stream
FROM unnest($1::timestamptz[], $2::bigint[], $3::integer[]) AS marker(seen, logindex, stream)
ORDER BY marker.stream, marker.logindex
ON CONFLICT (stream, logindex) DO NOTHING;`

func (cdb *PgDB) runShardBatch(ctx context.Context, shard int, queued []*LogEntry) (err error) {
	// Only one head or gap batch for a SHA prefix writes at a time.
	cdb.batchMu[shard].Lock()
	defer cdb.batchMu[shard].Unlock()
	err = cdb.runBatch(ctx, queued)
	return
}

func (cdb *PgDB) runGapBatches(ctx context.Context, entries []*LogEntry) (stored []bool, err error) {
	// A fetched tile can contain certificates from many worker shards.
	shards := make([][]int, max(1, cdb.workerCount))
	for i, le := range entries {
		shard := cdb.workerIndexFor(le)
		shards[shard] = append(shards[shard], i)
	}
	stored = make([]bool, len(entries))
	for shard, indexes := range shards {
		if len(indexes) == 0 {
			continue
		}
		if ctx.Err() != nil {
			err = errors.Join(err, ctx.Err())
			break
		}
		batch := make([]*LogEntry, len(indexes))
		for i, index := range indexes {
			batch[i] = entries[index]
		}
		if batchErr := cdb.runShardBatch(ctx, shard, batch); batchErr != nil {
			err = errors.Join(err, fmt.Errorf("batch shard %d: %w", shard, batchErr))
		} else {
			for _, index := range indexes {
				stored[index] = true
			}
		}
	}
	return
}

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
	var markerSeen []time.Time
	var markerIndexes []int64
	var markerStreams []int32
	type badCert struct {
		entry    *LogEntry
		seen     time.Time
		metadata badCertMetadata
	}
	var badCerts []badCert
	for _, le := range queued {
		if le.Certificate == nil || (!cutoff.IsZero() && !le.Certificate.NotAfter.After(cutoff)) {
			at := le.Seen
			if at.IsZero() {
				at = batchTime
			}
			at = at.UTC().Truncate(time.Second)
			if le.Certificate == nil && le.rawCert != nil {
				badCerts = append(badCerts, badCert{le, at, parseBadCertMetadata(le.rawCert)})
			}
			markerSeen = append(markerSeen, at)
			markerIndexes = append(markerIndexes, le.Index())
			markerStreams = append(markerStreams, le.LogStream.Id)
		} else {
			if len(b) > 1 {
				b = append(b, `,`...)
			}
			b = le.appendJSON(b)
		}
	}
	b = append(b, `]`...)
	var identOrgs, identProvs, identCountries []string
	if len(badCerts) > 0 {
		addIdent := func(ident [3]string) {
			identOrgs = append(identOrgs, ident[0])
			identProvs = append(identProvs, ident[1])
			identCountries = append(identCountries, ident[2])
		}
		for _, badCert := range badCerts {
			addIdent(badCert.metadata.issuer)
			addIdent(badCert.metadata.subject)
		}
		// The ingest function finds these identities in the same transaction,
		// so the batch acquires identity locks in one sorted pass.
		for _, le := range queued {
			if le.Certificate != nil && (cutoff.IsZero() || le.Certificate.NotAfter.After(cutoff)) {
				addIdent([3]string{
					strings.Join(le.Certificate.Issuer.Organization, ","),
					strings.Join(le.Certificate.Issuer.Province, ","),
					strings.Join(le.Certificate.Issuer.Country, ","),
				})
				addIdent([3]string{
					strings.Join(le.Certificate.Subject.Organization, ","),
					strings.Join(le.Certificate.Subject.Province, ","),
					strings.Join(le.Certificate.Subject.Country, ","),
				})
			}
		}
	}
	now := time.Now()
	// PostgreSQL aborts the whole implicit batch on a deadlock, so rebuild it
	// for each retry.
	for attempt := 0; attempt < 3; attempt++ {
		if len(markerSeen) == 0 {
			_, err = cdb.Exec(ctx, cdb.funcIngestBatch, string(b))
		} else {
			var batch pgx.Batch
			if len(badCerts) > 0 {
				batch.Queue(cdb.Pfx(insertBatchIdents), identOrgs, identProvs, identCountries)
			}
			for _, badCert := range badCerts {
				cdb.queueBadCert(&batch, badCert.entry, badCert.seen, badCert.metadata)
			}
			if len(markerSeen) != len(queued) {
				batch.Queue(cdb.funcIngestBatch, string(b))
			}
			batch.Queue(cdb.Pfx(insertSkippedEntries), markerSeen, markerIndexes, markerStreams)
			err = cdb.SendBatch(ctx, &batch).Close()
		}
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.SQLState() != "40P01" || attempt == 2 {
			break
		}
		if waitErr := sleep(ctx, time.Duration(attempt+1)*25*time.Millisecond); waitErr != nil {
			err = errors.Join(err, waitErr)
			break
		}
	}
	elapsed := time.Since(now)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.SQLState() == "22P02" {
		cdb.LogInfo("generated invalid JSON data", "json", string(b))
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
		var pendingErr error
		for !stop {
			ticked := false
			var flushAck chan error
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
				batchErr := cdb.LogError(cdb.runShardBatch(ctx, workerID, queued), "runBatch")
				if pendingErr == nil {
					pendingErr = batchErr
				}
				if flushAck != nil {
					flushAck <- pendingErr
					pendingErr = nil
					flushAck = nil
				}
				for _, le := range queued {
					if le.Certificate != nil {
						if batchErr != nil {
							le.Count.Add(-1)
							le.LogOperator.Count.Add(-1)
						} else if !stop {
							select {
							case <-ctx.Done():
								stop = true
							case cdb.getSendEntryCh() <- le:
							}
						}
					}
				}
				clear(queued)
				queued = queued[:0]
			}
			if flushAck != nil {
				flushAck <- pendingErr
				pendingErr = nil
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
