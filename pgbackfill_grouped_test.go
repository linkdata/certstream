package certstream

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/loglist3"
)

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
}

func TestBackfillAlignedGapRanges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     int
		missing   gap
		wantFetch []gap
		classic   bool
	}{
		{"tiled singleton", 512, gap{257, 257}, []gap{{256, 511}}, false},
		{"classic singleton", 512, gap{257, 257}, []gap{{256, 511}}, true},
		{"partial head tile", 271, gap{265, 265}, []gap{{256, 270}}, false},
		{"spanning tiles", 512, gap{250, 260}, []gap{{0, 255}, {256, 511}}, false},
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
			queueTestGaps(ls, []gap{tc.missing})
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
			for index := tc.missing.start; index <= tc.missing.end; index++ {
				want = append(want, index)
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
	if !gapsEqual(fetched, []gap{{256, 511}}) {
		t.Fatalf("fetches = %v, want one 256..511 attempt", fetched)
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
	if !gapsEqual(fetched, []gap{{256, 511}, {256, 511}}) {
		t.Fatalf("fetches = %v, want retry on next scan", fetched)
	}
	if got := queuedTestIndexes(ls); !slices.Equal(got, []int64{257, 263}) {
		t.Fatalf("retried indexes = %v, want [257 263]", got)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill after retry = %d, want 0", got)
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
}
