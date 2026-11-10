package certstream

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

type gapTileReadState struct {
	client     *sunlight.Client
	checkpoint torchwood.Checkpoint
	reader     *gapTileCacheReader
	tileStart  int64
	entries    []*sunlight.LogEntry
}

func (ls *LogStream) resetGapTileReader() {
	ls.gapReadMu.Lock()
	ls.gapRead = gapTileReadState{}
	ls.gapReadMu.Unlock()
}

type gapTileCacheReader struct {
	next  torchwood.TileReader
	tiles map[tlog.Tile][]byte
	order []tlog.Tile
}

func cacheGapHashTile(tile tlog.Tile) bool {
	return tile.L > 0 || tile.L == 0 && tile.W < sunlight.TileWidth
}

func (r *gapTileCacheReader) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	var missing []tlog.Tile
	var positions []int
	for i, tile := range tiles {
		if cacheGapHashTile(tile) {
			if cached, ok := r.tiles[tile]; ok {
				data[i] = cached
				continue
			}
		}
		missing = append(missing, tile)
		positions = append(positions, i)
	}
	if len(missing) > 0 {
		var fetched [][]byte
		if fetched, err = r.next.ReadTiles(ctx, missing); err == nil {
			for i, position := range positions {
				data[position] = fetched[i]
			}
		}
	}
	if err != nil {
		data = nil
	}
	return
}

func (r *gapTileCacheReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	var freshTiles []tlog.Tile
	var freshData [][]byte
	for i, tile := range tiles {
		// Upper and right-edge hash tiles recur across data tile reads.
		if cacheGapHashTile(tile) {
			if _, ok := r.tiles[tile]; ok {
				continue
			}
			if len(r.order) == 64 {
				delete(r.tiles, r.order[0])
				r.order = r.order[1:]
			}
			r.order = append(r.order, tile)
			r.tiles[tile] = bytes.Clone(data[i])
		}
		freshTiles = append(freshTiles, tile)
		freshData = append(freshData, data[i])
	}
	if len(freshTiles) > 0 {
		r.next.SaveTiles(freshTiles, freshData)
	}
}

func (r *gapTileCacheReader) ReadEndpoint(ctx context.Context, path string) ([]byte, error) {
	return r.next.ReadEndpoint(ctx, path)
}

func readGapTile(ctx context.Context, reader torchwood.TileReader, tree tlog.Tree, start int64) (entries []*sunlight.LogEntry, err error) {
	base := start / sunlight.TileWidth * sunlight.TileWidth
	width := int(min(sunlight.TileWidth, tree.N-base))
	tile := tlog.Tile{H: sunlight.TileHeight, L: -1, N: base / sunlight.TileWidth, W: width}
	var data [][]byte
	if data, err = reader.ReadTiles(ctx, []tlog.Tile{tile}); err == nil {
		indexes := make([]int64, width)
		for i := range indexes {
			indexes[i] = tlog.StoredHashIndex(0, base+int64(i))
		}
		var hashes []tlog.Hash
		// TileHashReader authenticates the hashes against the signed tree.
		if hashes, err = torchwood.TileHashReaderWithContext(ctx, tree, reader).ReadHashes(indexes); err == nil {
			entries = make([]*sunlight.LogEntry, 0, width)
			rest := data[0]
			for i := range width {
				var entry *sunlight.LogEntry
				if entry, rest, err = sunlight.ReadTileLeaf(rest); err != nil {
					break
				}
				if entry.LeafIndex != base+int64(i) || tlog.RecordHash(entry.MerkleTreeLeaf()) != hashes[i] {
					err = fmt.Errorf("data tile %d has invalid entry %d", tile.N, base+int64(i))
					break
				}
				entries = append(entries, entry)
			}
			if err == nil && len(rest) != 0 {
				err = fmt.Errorf("data tile %d has trailing bytes", tile.N)
			}
			if err == nil {
				reader.SaveTiles([]tlog.Tile{tile}, data)
			}
		}
	}
	if err != nil {
		entries = nil
	}
	return
}

func (ls *LogStream) getGapTileEntries(ctx context.Context, client *sunlight.Client, start, end int64, historical bool, handleFn handleLogEntryFn, gapcounter *atomic.Int64) (next int64, wanted bool) {
	ls.gapReadMu.Lock()
	defer ls.gapReadMu.Unlock()
	state := &ls.gapRead
	if state.client != client {
		*state = gapTileReadState{client: client}
	}
	next = start
	for next <= end {
		entryErr := ls.backoff.Retry(ctx, func() (err error) {
			if err = ls.waitForQueue(ctx, historical); err != nil {
				return
			}
			if state.checkpoint.N <= next {
				var checkpoint torchwood.Checkpoint
				if checkpoint, _, err = client.Checkpoint(ctx); err == nil {
					if checkpoint.Tree != state.checkpoint.Tree {
						state.entries = nil
					}
					if state.reader == nil {
						state.reader = &gapTileCacheReader{next: client.TileReader(), tiles: make(map[tlog.Tile][]byte)}
					}
					state.checkpoint = checkpoint
				}
			}
			if err == nil {
				if next >= state.checkpoint.N {
					return
				}
				var entries []*sunlight.LogEntry
				base := next / sunlight.TileWidth * sunlight.TileWidth
				if state.entries != nil && state.tileStart == base {
					entries = state.entries
				} else {
					if entries, err = readGapTile(ctx, state.reader, state.checkpoint.Tree, next); err == nil {
						state.tileStart = base
						state.entries = entries
					}
				}
				if err == nil {
					for i, entry := range entries {
						index := base + int64(i)
						if index < next {
							continue
						}
						if index > end {
							break
						}
						le := ls.makeTileLogEntry(index, entry, historical)
						ls.seeIndex(index)
						if handleFn(ctx, time.Now(), le) {
							wanted = true
						}
						next = index + 1
						if gapcounter != nil {
							gapcounter.Add(-1)
						}
					}
				} else {
					// A published full tile may replace a partial tile. Refresh the
					// checkpoint on retry, while keeping verified hash tiles.
					state.checkpoint = torchwood.Checkpoint{}
					state.entries = nil
				}
			}
			if err != nil {
				if !ls.handleStreamError(err, "getGapTileEntries") {
					err = wrapLogStreamRetryable(err)
				}
			}
			return
		})
		if entryErr != nil {
			if gapcounter != nil {
				if ctx.Err() == nil {
					_ = ls.LogError(entryErr, "gap not fillable", "url", ls.URL(), "start", next, "end", end)
				}
				gapcounter.Add(next - (end + 1))
			}
			break
		}
		if next >= state.checkpoint.N {
			if gapcounter != nil {
				gapcounter.Add(next - (end + 1))
			}
			break
		}
	}
	return
}
