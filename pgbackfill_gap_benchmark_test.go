package certstream

import (
	"testing"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/loglist3"
)

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
