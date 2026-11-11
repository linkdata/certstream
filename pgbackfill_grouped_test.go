package certstream

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/loglist3"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jackc/pgx/v5/pgconn"
)

func newGapTestEntry(ls *LogStream, index int64, now time.Time) *LogEntry {
	sig := make([]byte, 32)
	sig[0] = byte(index)
	binary.BigEndian.PutUint64(sig[24:], uint64(index+1))
	return &LogEntry{
		LogStream:   ls,
		LogIndex:    index,
		Certificate: &ctx509.Certificate{Signature: sig, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
		Signature:   sig,
		Seen:        now,
	}
}

func queueTestGaps(ls *LogStream, gaps []gap) {
	ls.gapCh = make(chan gap, len(gaps))
	var count int64
	for _, g := range gaps {
		ls.gapCh <- g
		count += g.end - g.start + 1
	}
	close(ls.gapCh)
	ls.Backfill.Store(count)
}

func queuedTestIndexes(ls *LogStream) (indexes []int64) {
	for len(ls.sendEntryCh) > 0 {
		indexes = append(indexes, (<-ls.sendEntryCh).LogIndex)
	}
	return
}

func TestBackfillGroupsTiledHoles(t *testing.T) {
	ls, transport := newTileTestStream(t, 2*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, sunlight.TileWidth)
	ls.LastIndex.Store(2*sunlight.TileWidth - 1)
	queueTestGaps(ls, []gap{{257, 257}, {263, 263}, {500, 500}})

	if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, ls.getGapEntries, nil, false); err != nil {
		t.Fatal(err)
	}
	if got, want := queuedTestIndexes(ls), []int64{257, 263, 500}; !slices.Equal(got, want) {
		t.Fatalf("queued indexes = %v, want %v", got, want)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
	if got := transport.dataTileCalls.Load(); got != 1 {
		t.Fatalf("data tile requests = %d, want 1", got)
	}
	if ls.gapRead.reader != nil || ls.gapRead.entries != nil {
		t.Fatal("gap tile cache retained after scan")
	}
}

func TestBackfillSparseTiledHolesFetchOnlyMissingTiles(t *testing.T) {
	ls, transport := newTileTestStream(t, 100*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, 2)
	ls.LastIndex.Store(100*sunlight.TileWidth - 1)
	queueTestGaps(ls, []gap{{sunlight.TileWidth, sunlight.TileWidth}, {49 * sunlight.TileWidth, 49 * sunlight.TileWidth}})

	if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, ls.getGapEntries, nil, false); err != nil {
		t.Fatal(err)
	}
	if got, want := queuedTestIndexes(ls), []int64{sunlight.TileWidth, 49 * sunlight.TileWidth}; !slices.Equal(got, want) {
		t.Fatalf("queued indexes = %v, want %v", got, want)
	}
	if got := transport.dataTileCalls.Load(); got != 2 {
		t.Fatalf("data tile requests = %d, want 2", got)
	}
	if got := transport.requests.Load(); got != 6 {
		t.Fatalf("HTTP requests = %d, want 6", got)
	}
}

func TestBackfillSparseTiledHolesWithLaggingHead(t *testing.T) {
	ls, transport := newTileTestStream(t, 100*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, 4)
	ls.LastIndex.Store(4*sunlight.TileWidth - 1)
	queueTestGaps(ls, []gap{{0, 0}, {sunlight.TileWidth, sunlight.TileWidth}, {2 * sunlight.TileWidth, 2 * sunlight.TileWidth}, {3 * sunlight.TileWidth, 3 * sunlight.TileWidth}})

	if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, ls.getGapEntries, nil, false); err != nil {
		t.Fatal(err)
	}
	if got := transport.dataTileCalls.Load(); got != 4 {
		t.Fatalf("data tile requests = %d, want 4", got)
	}
	if got := transport.requests.Load(); got != 10 {
		t.Fatalf("HTTP requests = %d, want 10", got)
	}
}

func TestBackfillSparseMixedTiledHoles(t *testing.T) {
	ls, transport := newTileTestStream(t, 100*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, 3)
	ls.LastIndex.Store(100*sunlight.TileWidth - 1)
	queueTestGaps(ls, []gap{{50 * sunlight.TileWidth, 50 * sunlight.TileWidth}, {99 * sunlight.TileWidth, 99*sunlight.TileWidth + 1}})

	if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, ls.getGapEntries, nil, false); err != nil {
		t.Fatal(err)
	}
	if got := transport.dataTileCalls.Load(); got != 2 {
		t.Fatalf("data tile requests = %d, want 2", got)
	}
}

func TestBackfillTiledHoleBehindGapCheckpoint(t *testing.T) {
	ls, transport := newTileTestStream(t, sunlight.TileWidth+15)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, 1)
	ls.LastIndex.Store(2*sunlight.TileWidth - 1)
	queueTestGaps(ls, []gap{{sunlight.TileWidth + 9, sunlight.TileWidth + 9}})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := (&PgDB{}).backfillGapsWithFetcherMode(ctx, ls, ls.getGapEntries, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("hole fetch waited for the gap checkpoint: %v", err)
	}
	if got, want := queuedTestIndexes(ls), []int64{sunlight.TileWidth + 9}; !slices.Equal(got, want) {
		t.Fatalf("queued indexes = %v, want %v", got, want)
	}
	if got := transport.dataTileCalls.Load(); got != 1 {
		t.Fatalf("data tile requests = %d, want 1", got)
	}
}

func TestBackfillCachesPartialRightEdgeHashTile(t *testing.T) {
	const count = 100*sunlight.TileWidth + 15
	ls, transport := newTileTestStream(t, count)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, 3)
	ls.LastIndex.Store(count - 1)
	queueTestGaps(ls, []gap{
		{sunlight.TileWidth, sunlight.TileWidth},
		{2 * sunlight.TileWidth, 2 * sunlight.TileWidth},
		{3 * sunlight.TileWidth, 3 * sunlight.TileWidth},
	})

	if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, ls.getGapEntries, nil, false); err != nil {
		t.Fatal(err)
	}
	if got := transport.dataTileCalls.Load(); got != 3 {
		t.Fatalf("data tile requests = %d, want 3", got)
	}
	if got := transport.requests.Load(); got != 9 {
		t.Fatalf("HTTP requests = %d, want 9", got)
	}
}

func TestBackfillAlignedGapRanges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     int
		missing   []gap
		wantFetch []gap
		classic   bool
	}{
		{"tiled singleton", 512, []gap{{257, 257}}, []gap{{257, 257}}, false},
		{"classic singleton", 512, []gap{{257, 257}}, []gap{{256, 511}}, true},
		{"partial head tile", 271, []gap{{265, 265}}, []gap{{265, 265}}, false},
		{"spanning tiled", 512, []gap{{250, 260}}, []gap{{250, 255}, {256, 260}}, false},
		{"spanning classic", 512, []gap{{250, 260}}, []gap{{0, 255}, {256, 511}}, true},
		{"four full classic tiles", 1536, []gap{{256, 1279}}, []gap{{256, 1279}}, true},
		{"five full classic tiles", 1536, []gap{{256, 1535}}, []gap{{256, 1279}, {1280, 1535}}, true},
		{"partial classic tile", 1024, []gap{{0, 255}, {256, 257}, {512, 767}}, []gap{{0, 255}, {256, 511}, {512, 767}}, true},
		{"separated full classic tiles", 1024, []gap{{0, 255}, {512, 767}}, []gap{{0, 255}, {512, 767}}, true},
		{"sparse tiled", 1024, []gap{{257, 257}, {768, 768}}, []gap{{257, 257}, {768, 768}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ls, transport := newTileTestStream(t, tc.count)
			if tc.classic {
				ls.gapTile = nil
			} else {
				ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
			}
			ls.sendEntryCh = make(chan *LogEntry, tc.count)
			ls.LastIndex.Store(int64(tc.count - 1))
			queueTestGaps(ls, tc.missing)
			var fetched []gap
			fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
				fetched = append(fetched, gap{start, end})
				for index := start; index <= end; index++ {
					handle(ctx, time.Now(), ls.makeTileLogEntry(index, transport.entries[index], true))
					if remaining != nil {
						remaining.Add(-1)
					}
				}
				return end + 1, true
			}
			if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, fetch, nil, false); err != nil {
				t.Fatal(err)
			}
			if !gapsEqual(fetched, tc.wantFetch) {
				t.Fatalf("fetches = %v, want %v", fetched, tc.wantFetch)
			}
			var want []int64
			for _, g := range tc.missing {
				for index := g.start; index <= g.end; index++ {
					want = append(want, index)
				}
			}
			if got := queuedTestIndexes(ls); !slices.Equal(got, want) {
				t.Fatalf("queued indexes = %v, want %v", got, want)
			}
			if got := ls.Backfill.Load(); got != 0 {
				t.Fatalf("Backfill = %d, want 0", got)
			}
		})
	}
}

func TestBackfillGroupedPartialFetch(t *testing.T) {
	ls, transport := newTileTestStream(t, 2*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, sunlight.TileWidth)
	ls.LastIndex.Store(2*sunlight.TileWidth - 1)
	queueTestGaps(ls, []gap{{257, 257}, {263, 263}})
	var fetched []gap
	partial := true
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		fetched = append(fetched, gap{start, end})
		next := end + 1
		if partial {
			next = 261
		}
		for index := start; index < next; index++ {
			handle(ctx, time.Now(), ls.makeTileLogEntry(index, transport.entries[index], true))
			if remaining != nil {
				remaining.Add(-1)
			}
		}
		return next, true
	}
	if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, fetch, nil, false); !errors.Is(err, errGapIncomplete) {
		t.Fatalf("backfill error = %v, want %v", err, errGapIncomplete)
	}
	if !gapsEqual(fetched, []gap{{257, 263}}) {
		t.Fatalf("fetches = %v, want one gap-bearing range", fetched)
	}
	if got := queuedTestIndexes(ls); !slices.Equal(got, []int64{257}) {
		t.Fatalf("queued indexes = %v, want [257]", got)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}

	partial = false
	queueTestGaps(ls, []gap{{257, 257}, {263, 263}})
	if err := (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, fetch, nil, false); err != nil {
		t.Fatal(err)
	}
	if !gapsEqual(fetched, []gap{{257, 263}, {257, 263}}) {
		t.Fatalf("fetches = %v, want retry on next scan", fetched)
	}
	if got := queuedTestIndexes(ls); !slices.Equal(got, []int64{257, 263}) {
		t.Fatalf("retried indexes = %v, want [257 263]", got)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill after retry = %d, want 0", got)
	}
}

func TestBackfillClassicFullGroupPartialFetchKeepsCursor(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.LastIndex.Store(1023)
	queueTestGaps(ls, []gap{{0, 1023}})
	now := time.Now().UTC()
	limit := int64(512)
	var fetched []gap
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		fetched = append(fetched, gap{start, end})
		next := min(end+1, limit)
		for index := start; index < next; index++ {
			handle(ctx, now, newGapTestEntry(ls, index, now))
			remaining.Add(-1)
		}
		return next, true
	}
	check := func(want int64) {
		t.Helper()
		var cursor, count int64
		err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
(SELECT count(*) FROM CERTDB_entry WHERE stream = $1)
FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor, &count)
		if err != nil {
			t.Fatal(err)
		}
		if cursor != want || count != want {
			t.Fatalf("cursor=%d, stored=%d; want both %d", cursor, count, want)
		}
	}
	if err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false); !errors.Is(err, errGapIncomplete) {
		t.Fatalf("partial fetch error = %v, want %v", err, errGapIncomplete)
	}
	if !gapsEqual(fetched, []gap{{0, 1023}}) {
		t.Fatalf("fetches = %v, want one grouped range", fetched)
	}
	check(512)

	limit = 1024
	queueTestGaps(ls, []gap{{512, 1023}})
	if err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false); err != nil {
		t.Fatal(err)
	}
	if !gapsEqual(fetched, []gap{{0, 1023}, {512, 1023}}) {
		t.Fatalf("fetches after retry = %v", fetched)
	}
	check(1024)
}

func TestBackfillClassicFullGroupPartialShardFailureKeepsCursor(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	installShardIngestProbe(t, db, 1)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.LastIndex.Store(1023)
	queueTestGaps(ls, []gap{{0, 1023}})
	now := time.Now().UTC()
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		for index := start; index <= end; index++ {
			entry := newGapTestEntry(ls, index, now)
			if index < 512 {
				entry.Signature[0] = 0
			} else {
				entry.Signature[0] = 8
			}
			handle(ctx, now, entry)
			remaining.Add(-1)
		}
		return end + 1, true
	}
	err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22012" {
		t.Fatalf("backfill error = %v, want test shard failure", err)
	}
	var cursor, count int64
	err = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex,
(SELECT count(*) FROM CERTDB_entry WHERE stream = $1)
FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor, &count)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 512 || count != 512 {
		t.Fatalf("cursor=%d, stored=%d; want both 512", cursor, count)
	}
}

func TestBackfillFetchesBeforeScanCloses(t *testing.T) {
	ls := &LogStream{LogOperator: &LogOperator{CertStream: &CertStream{}}}
	ls.LastIndex.Store(255)
	ls.gapCh = make(chan gap, 1)
	ls.gapCh <- gap{start: 1, end: 1}
	closed := false
	defer func() {
		if !closed {
			close(ls.gapCh)
		}
	}()
	ls.Backfill.Store(1)
	fetched := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls,
			func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, _ *atomic.Int64) (int64, bool) {
				close(fetched)
				return end + 1, true
			}, nil, false)
	}()
	select {
	case <-fetched:
	case <-time.After(time.Second):
		t.Fatal("gap fetch waited for scan to close")
	}
	close(ls.gapCh)
	closed = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
}

func TestBackfillReusesTileWhileScanIsOpen(t *testing.T) {
	ls, transport := newTileTestStream(t, 2*sunlight.TileWidth)
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.sendEntryCh = make(chan *LogEntry, 2)
	ls.LastIndex.Store(2*sunlight.TileWidth - 1)
	ls.gapCh = make(chan gap)
	closed := false
	defer func() {
		if !closed {
			close(ls.gapCh)
		}
	}()
	done := make(chan error, 1)
	go func() {
		done <- (&PgDB{}).backfillGapsWithFetcherMode(t.Context(), ls, ls.getGapEntries, nil, false)
	}()
	for _, index := range []int64{257, 263} {
		ls.Backfill.Add(1)
		ls.gapCh <- gap{start: index, end: index}
		select {
		case got := <-ls.sendEntryCh:
			if got.LogIndex != index {
				t.Fatalf("entry index = %d, want %d", got.LogIndex, index)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("entry %d was not fetched before scan closed", index)
		}
	}
	close(ls.gapCh)
	closed = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := transport.dataTileCalls.Load(); got != 1 {
		t.Fatalf("data tile requests = %d, want 1", got)
	}
	if got := transport.requests.Load(); got != 4 {
		t.Fatalf("HTTP requests = %d, want 4", got)
	}
}
