package certstream

import (
	"context"
	"testing"
	"time"

	"filippo.io/sunlight"
	"golang.org/x/mod/sumdb/tlog"
)

func TestReadGapTileVerifiesPartialTile(t *testing.T) {
	ls, transport := newTileTestStream(t, sunlight.TileWidth+15)
	checkpoint, _, err := ls.gapTile.Checkpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := readGapTile(t.Context(), ls.gapTile.TileReader(), checkpoint.Tree, sunlight.TileWidth)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 15 {
		t.Fatalf("partial tile has %d entries, want 15", len(entries))
	}
	if entries[14].LeafIndex != sunlight.TileWidth+14 {
		t.Fatalf("partial tile last index = %d, want %d", entries[14].LeafIndex, sunlight.TileWidth+14)
	}
	if got := transport.dataTileCalls.Load(); got != 1 {
		t.Fatalf("data tile requests = %d, want 1", got)
	}
}

func TestReadGapTileRejectsTamperedEntry(t *testing.T) {
	ls, transport := newTileTestStream(t, sunlight.TileWidth)
	checkpoint, _, err := ls.gapTile.Checkpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tampered := *transport.entries[100]
	tampered.Certificate = []byte{1, 2, 3}
	transport.entries[100] = &tampered
	entries, err := readGapTile(t.Context(), ls.gapTile.TileReader(), checkpoint.Tree, 0)
	if err == nil || entries != nil {
		t.Fatalf("tampered tile = (%d entries, %v), want verification error", len(entries), err)
	}
}

func TestGapTileReaderRefreshesGrowingPartialTile(t *testing.T) {
	ls, transport := newTileTestStream(t, 2*sunlight.TileWidth+30)
	transport.setCheckpoint(t, 2*sunlight.TileWidth+15)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var seen []int64
	handle := func(_ context.Context, _ time.Time, entry *LogEntry) bool {
		seen = append(seen, entry.Index())
		return true
	}
	if next, wanted := ls.getGapEntries(ctx, 517, 517, true, handle, nil); next != 518 || !wanted {
		t.Fatalf("first gap: next = %d, wanted = %t", next, wanted)
	}
	reader := ls.gapRead.reader
	if reader == nil || len(reader.tiles) == 0 {
		t.Fatal("first gap did not cache verified hash tiles")
	}
	transport.setCheckpoint(t, 2*sunlight.TileWidth+30)
	before := transport.requests.Load()
	if next, wanted := ls.getGapEntries(ctx, 530, 530, true, handle, nil); next != 531 || !wanted {
		t.Fatalf("grown gap: next = %d, wanted = %t", next, wanted)
	}
	cachedRequests := transport.requests.Load() - before
	if ls.gapRead.reader != reader {
		t.Fatal("growing checkpoint discarded the verified hash cache")
	}
	if len(seen) != 2 || seen[0] != 517 || seen[1] != 530 {
		t.Fatalf("seen = %v, want [517 530]", seen)
	}
	if got := transport.dataTileCalls.Load(); got != 2 {
		t.Fatalf("data tile requests = %d, want 2", got)
	}
	before = transport.requests.Load()
	checkpoint, _, err := ls.gapTile.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readGapTile(ctx, ls.gapTile.TileReader(), checkpoint.Tree, 530); err != nil {
		t.Fatal(err)
	}
	freshRequests := transport.requests.Load() - before
	if cachedRequests >= freshRequests {
		t.Fatalf("grown tile requests with cache = %d, fresh = %d", cachedRequests, freshRequests)
	}
}

func TestGapTileReaderRetriesFailedVerification(t *testing.T) {
	ls, transport := newTileTestStream(t, 3*sunlight.TileWidth+15)
	ls.backoff = newLogStreamBackoff(time.Millisecond, 10*time.Millisecond, 2, false)
	transport.corruptDataOnce.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var seen []int64
	next, wanted := ls.getGapEntries(ctx, 100, 100, true, func(_ context.Context, _ time.Time, entry *LogEntry) bool {
		seen = append(seen, entry.Index())
		return true
	}, nil)
	if next != 101 || !wanted || len(seen) != 1 || seen[0] != 100 {
		t.Fatalf("retry: next = %d, wanted = %t, seen = %v", next, wanted, seen)
	}
	if got := transport.dataTileCalls.Load(); got != 2 {
		t.Fatalf("data tile requests = %d, want 2", got)
	}
	retryRequests := transport.requests.Load()
	before := retryRequests
	checkpoint, _, err := ls.gapTile.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readGapTile(ctx, ls.gapTile.TileReader(), checkpoint.Tree, 100); err != nil {
		t.Fatal(err)
	}
	freshRequests := transport.requests.Load() - before
	if retryRequests >= 2*freshRequests {
		t.Fatalf("retry HTTP requests = %d, two fresh reads = %d", retryRequests, 2*freshRequests)
	}
}

func TestGapTileReaderRefreshesAfterPartialTileDisappears(t *testing.T) {
	ls, transport := newTileTestStream(t, 2*sunlight.TileWidth+30)
	transport.setCheckpoint(t, 2*sunlight.TileWidth+15)
	ls.backoff = newLogStreamBackoff(time.Millisecond, 10*time.Millisecond, 2, false)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var seen []int64
	handle := func(_ context.Context, _ time.Time, entry *LogEntry) bool {
		seen = append(seen, entry.Index())
		return true
	}
	if next, wanted := ls.getGapEntries(ctx, 0, 0, true, handle, nil); next != 1 || !wanted {
		t.Fatalf("first gap: next = %d, wanted = %t", next, wanted)
	}
	transport.setCheckpoint(t, 2*sunlight.TileWidth+30)
	transport.denyDataTile = &tlog.Tile{H: sunlight.TileHeight, L: -1, N: 2, W: 15}
	if next, wanted := ls.getGapEntries(ctx, 520, 520, true, handle, nil); next != 521 || !wanted {
		t.Fatalf("grown gap: next = %d, wanted = %t, context = %v", next, wanted, ctx.Err())
	}
	if len(seen) != 2 || seen[0] != 0 || seen[1] != 520 {
		t.Fatalf("seen = %v, want [0 520]", seen)
	}
	if got := transport.dataTileCalls.Load(); got != 3 {
		t.Fatalf("data tile requests = %d, want 3 including missing partial tile", got)
	}
	if got := ls.gapRead.checkpoint.N; got != 2*sunlight.TileWidth+30 {
		t.Fatalf("checkpoint size = %d, want %d", got, 2*sunlight.TileWidth+30)
	}
}

func TestGapTileReaderUsesCheckpointUntilBoundary(t *testing.T) {
	const count = 3*sunlight.TileWidth + 15
	ls, transport := newTileTestStream(t, count)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	next, wanted := ls.getGapEntries(ctx, sunlight.TileWidth, 5*sunlight.TileWidth, true,
		func(context.Context, time.Time, *LogEntry) bool { return true }, nil)
	if next != count || !wanted {
		t.Fatalf("range result: next = %d, wanted = %t", next, wanted)
	}
	if got := transport.checkpointCalls.Load(); got != 1 {
		t.Fatalf("checkpoint requests = %d, want one for the covered prefix", got)
	}
}

func BenchmarkGapTileReadBeyondCheckpoint(b *testing.B) {
	const count = 3*sunlight.TileWidth + 15
	ls, transport := newTileTestStream(b, count)
	handle := func(context.Context, time.Time, *LogEntry) bool { return true }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ls.resetGapTileReader()
		next, wanted := ls.getGapEntries(b.Context(), sunlight.TileWidth, 5*sunlight.TileWidth, true, handle, nil)
		if next != count || !wanted {
			b.Fatalf("range result: next = %d, wanted = %t", next, wanted)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(transport.checkpointCalls.Load())/float64(b.N), "checkpoints/op")
	b.ReportMetric(float64(transport.requests.Load())/float64(b.N), "http-requests/op")
}
