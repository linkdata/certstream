package certstream

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/loglist3"
)

func BenchmarkBackfillClassicFullGapTiles(b *testing.B) {
	const tiles = 4
	ctx, db, cs, streamID, _ := cleanTestFixture(b)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	now := time.Now().UTC()
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		for index := start; index <= end; index++ {
			handle(ctx, now, newGapTestEntry(ls, index, now))
			remaining.Add(-1)
		}
		return end + 1, true
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		start := int64(i * tiles * sunlight.TileWidth)
		end := start + tiles*sunlight.TileWidth - 1
		ls.LastIndex.Store(end)
		queueTestGaps(ls, []gap{{start: start, end: end}})
		if err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false); err != nil {
			b.Fatal(err)
		}
		if got := ls.Backfill.Load(); got != 0 {
			b.Fatalf("Backfill = %d, want 0", got)
		}
	}
}

// BenchmarkBackfillClassicGapPrefetch measures three full classic gap groups with
// simulated request latency and real PostgreSQL ingest batches.
func BenchmarkBackfillClassicGapPrefetch(b *testing.B) {
	const tiles = 3 * classicGapBatchTiles
	ctx, db, cs, streamID, _ := cleanTestFixture(b)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	now := time.Now().UTC()
	fetch := gapPrefetchBenchmarkFetcher(ls, now)

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		start := int64(i * tiles * sunlight.TileWidth)
		end := start + tiles*sunlight.TileWidth - 1
		ls.LastIndex.Store(end)
		queueTestGaps(ls, []gap{{start: start, end: end}})
		if err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false); err != nil {
			b.Fatal(err)
		}
		if got := ls.Backfill.Load(); got != 0 {
			b.Fatalf("Backfill = %d, want 0", got)
		}
	}
}

// BenchmarkBackfillClassicGapPrefetchParallel measures lookahead across streams.
func BenchmarkBackfillClassicGapPrefetchParallel(b *testing.B) {
	const tiles = 3 * classicGapBatchTiles
	ctx, db, cs, firstID, _ := cleanTestFixture(b)
	streamIDs := make([]int32, runtime.GOMAXPROCS(0))
	streamIDs[0] = firstID
	for i := 1; i < len(streamIDs); i++ {
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_stream (url, operator, json)
SELECT $1, operator, '{}' FROM CERTDB_stream WHERE id = $2 RETURNING id`),
			fmt.Sprintf("https://example.com/log-%d", i), firstID).Scan(&streamIDs[i]); err != nil {
			b.Fatal(err)
		}
	}
	now := time.Now().UTC()
	var nextWorker atomic.Int32
	errCh := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		worker := int(nextWorker.Add(1)) - 1
		if worker >= len(streamIDs) {
			reportErr(fmt.Errorf("parallel worker %d exceeds %d streams", worker, len(streamIDs)))
			return
		}
		ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamIDs[worker]}
		fetch := gapPrefetchBenchmarkFetcher(ls, now)
		var iteration int64
		for pb.Next() {
			start := int64(worker+1)*1_048_576 + iteration*tiles*sunlight.TileWidth
			end := start + tiles*sunlight.TileWidth - 1
			iteration++
			ls.LastIndex.Store(end)
			queueTestGaps(ls, []gap{{start: start, end: end}})
			if err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false); err != nil {
				reportErr(err)
				return
			}
			if got := ls.Backfill.Load(); got != 0 {
				reportErr(fmt.Errorf("Backfill = %d, want 0", got))
				return
			}
		}
	})
	select {
	case err := <-errCh:
		b.Fatal(err)
	default:
	}
}

func gapPrefetchBenchmarkFetcher(ls *LogStream, now time.Time) rawEntriesFetcher {
	return func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		// One 50ms request per 256-entry tile represents network latency.
		for tile := start; tile <= end; tile += sunlight.TileWidth {
			if sleep(ctx, 50*time.Millisecond) != nil {
				return tile, false
			}
		}
		for index := start; index <= end; index++ {
			handle(ctx, now, newGapTestEntry(ls, index, now))
			remaining.Add(-1)
		}
		return end + 1, true
	}
}

func BenchmarkBackfillTiledSingletonGaps(b *testing.B) {
	const holes = 32
	ls, transport := newTileTestStream(b, 2*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, sunlight.TileWidth)
	ls.LastIndex.Store(2*sunlight.TileWidth - 1)
	db := &PgDB{}
	ctx := b.Context()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ls.gapCh = make(chan gap, holes)
		for i := range holes {
			index := int64(sunlight.TileWidth + i*8)
			ls.gapCh <- gap{start: index, end: index}
		}
		close(ls.gapCh)
		ls.Backfill.Store(holes)
		if err := db.backfillGapsWithFetcherMode(ctx, ls, ls.getGapEntries, nil, false); err != nil {
			b.Fatal(err)
		}
		if got := ls.Backfill.Load(); got != 0 {
			b.Fatalf("Backfill = %d, want 0", got)
		}
		if got := len(ls.sendEntryCh); got != holes {
			b.Fatalf("queued entries = %d, want %d", got, holes)
		}
		for range holes {
			<-ls.sendEntryCh
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(transport.requests.Load())/float64(b.N), "http-requests/op")
	b.ReportMetric(float64(transport.dataTileCalls.Load())/float64(b.N), "data-tiles/op")
}

func BenchmarkBackfillTiledTrickledGaps(b *testing.B) {
	const holes = 32
	ls, transport := newTileTestStream(b, 2*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, 1)
	ls.LastIndex.Store(2*sunlight.TileWidth - 1)
	db := &PgDB{}
	ctx := b.Context()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ls.gapCh = make(chan gap)
		done := make(chan error, 1)
		go func() {
			done <- db.backfillGapsWithFetcherMode(ctx, ls, ls.getGapEntries, nil, false)
		}()
		for i := range holes {
			index := int64(sunlight.TileWidth + i*8)
			ls.Backfill.Add(1)
			ls.gapCh <- gap{start: index, end: index}
			if got := (<-ls.sendEntryCh).LogIndex; got != index {
				b.Fatalf("entry index = %d, want %d", got, index)
			}
		}
		close(ls.gapCh)
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		if got := ls.Backfill.Load(); got != 0 {
			b.Fatalf("Backfill = %d, want 0", got)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(transport.requests.Load())/float64(b.N), "http-requests/op")
	b.ReportMetric(float64(transport.dataTileCalls.Load())/float64(b.N), "data-tiles/op")
}

func BenchmarkBackfillTiledContiguousGap(b *testing.B) {
	const start = int64(sunlight.TileWidth)
	const length = 8192
	const end = start + length - 1
	benchmarkBackfillTiledGapBatch(b, int(end+1), []gap{{start: start, end: end}})
}

func BenchmarkBackfillTiledLargeContiguousGap(b *testing.B) {
	const start = int64(sunlight.TileWidth)
	const length = 128 * sunlight.TileWidth
	const end = start + length - 1
	benchmarkBackfillTiledGapBatch(b, int(end+1), []gap{{start: start, end: end}})
}

func BenchmarkBackfillTiledPartialTreeGap(b *testing.B) {
	const start = int64(sunlight.TileWidth)
	const length = 50 * sunlight.TileWidth
	const end = start + length - 1
	benchmarkBackfillTiledGapBatch(b, 100*sunlight.TileWidth+15, []gap{{start: start, end: end}})
}

func BenchmarkBackfillTiledSpacedGaps(b *testing.B) {
	const holes = 32
	gaps := make([]gap, holes)
	for i := range gaps {
		index := int64((i + 1) * sunlight.TileWidth)
		gaps[i] = gap{start: index, end: index}
	}
	benchmarkBackfillTiledGapBatch(b, (holes+1)*sunlight.TileWidth, gaps)
}

func BenchmarkBackfillTiledSparseGaps(b *testing.B) {
	benchmarkBackfillTiledGapBatch(b, 100*sunlight.TileWidth, []gap{
		{start: sunlight.TileWidth, end: sunlight.TileWidth},
		{start: 49 * sunlight.TileWidth, end: 49 * sunlight.TileWidth},
	})
}

func benchmarkBackfillTiledGapBatch(b *testing.B, count int, gaps []gap) {
	missing := 0
	for _, g := range gaps {
		missing += int(g.end - g.start + 1)
	}
	ls, transport := newTileTestStream(b, count)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, missing)
	ls.LastIndex.Store(int64(count - 1))
	db := &PgDB{}
	ctx := b.Context()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ls.gapCh = make(chan gap, len(gaps))
		for _, g := range gaps {
			ls.gapCh <- g
		}
		close(ls.gapCh)
		ls.Backfill.Store(int64(missing))
		if err := db.backfillGapsWithFetcherMode(ctx, ls, ls.getGapEntries, nil, false); err != nil {
			b.Fatal(err)
		}
		if got := ls.Backfill.Load(); got != 0 {
			b.Fatalf("Backfill = %d, want 0", got)
		}
		if got := len(ls.sendEntryCh); got != missing {
			b.Fatalf("queued entries = %d, want %d", got, missing)
		}
		for range missing {
			<-ls.sendEntryCh
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(transport.requests.Load())/float64(b.N), "http-requests/op")
	b.ReportMetric(float64(transport.dataTileCalls.Load())/float64(b.N), "data-tiles/op")
}
