package certstream

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type tileHashStore struct {
	hashes map[int64]tlog.Hash
}

type tileRoundTripper struct {
	entries         []*sunlight.LogEntry
	hashStore       *tileHashStore
	checkpoint      []byte
	partialHashTile map[tlog.Tile]bool
	requests        atomic.Int64
	dataTileCalls   atomic.Int64
}

type injectedSigner struct {
	v   note.Verifier
	sig []byte
}

func (s *injectedSigner) Sign(msg []byte) ([]byte, error) {
	return s.sig, nil
}

func (s *injectedSigner) Name() string {
	return s.v.Name()
}

func (s *injectedSigner) KeyHash() uint32 {
	return s.v.KeyHash()
}

func (s *injectedSigner) Verifier() note.Verifier {
	return s.v
}

func newTileHashStore(recordHashes []tlog.Hash) (store *tileHashStore, err error) {
	store = &tileHashStore{hashes: make(map[int64]tlog.Hash)}
	hashReader := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		return store.readHashes(indexes)
	})
	for i, recordHash := range recordHashes {
		if err == nil {
			var hashes []tlog.Hash
			hashes, err = tlog.StoredHashesForRecordHash(int64(i), recordHash, hashReader)
			if err == nil {
				base := tlog.StoredHashIndex(0, int64(i))
				for j, hash := range hashes {
					store.hashes[base+int64(j)] = hash
				}
			}
		}
	}
	if err != nil {
		store = nil
	}
	return
}

func (store *tileHashStore) readHashes(indexes []int64) (hashes []tlog.Hash, err error) {
	hashes = make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if err == nil {
			var ok bool
			hashes[i], ok = store.hashes[idx]
			if !ok {
				err = errors.New("tile hash index missing")
			}
		}
	}
	if err != nil {
		hashes = nil
	}
	return
}

func signTreeHead(priv *ecdsa.PrivateKey, input []byte) (sig []byte, err error) {
	hash := sha256.Sum256(input)
	var signature []byte
	signature, err = priv.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err == nil {
		var b cryptobyte.Builder
		b.AddUint8(4)
		b.AddUint8(3)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(signature)
		})
		sig, err = b.Bytes()
	}
	return
}

func noteSignature(timestamp uint64, treeSignature []byte) (sig []byte, err error) {
	var b cryptobyte.Builder
	b.AddUint64(timestamp)
	b.AddBytes(treeSignature)
	sig, err = b.Bytes()
	return
}

func mustSignedCheckpoint(t testing.TB, name string, priv *ecdsa.PrivateKey, tree tlog.Tree) (noteBytes []byte) {
	t.Helper()
	var err error
	timestamp := uint64(time.Now().UnixMilli())
	sth := ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       uint64(tree.N),
		Timestamp:      timestamp,
		SHA256RootHash: ct.SHA256Hash(tree.Hash),
	}
	var sthInput []byte
	if sthInput, err = ct.SerializeSTHSignatureInput(sth); err == nil {
		var treeSig []byte
		if treeSig, err = signTreeHead(priv, sthInput); err == nil {
			var sig []byte
			if sig, err = noteSignature(timestamp, treeSig); err == nil {
				var verifier note.Verifier
				if verifier, err = sunlight.NewRFC6962Verifier(name, priv.Public()); err == nil {
					signer := &injectedSigner{v: verifier, sig: sig}
					noteBytes, err = note.Sign(&note.Note{
						Text: (torchwood.Checkpoint{
							Origin: name,
							Tree:   tree,
						}).String(),
					}, signer)
				}
			}
		}
	}
	if err != nil {
		t.Fatalf("checkpoint sign failed: %v", err)
	}
	return
}

func (rt *tileRoundTripper) dataTile(tile tlog.Tile) (data []byte, err error) {
	if tile.L == -1 {
		start := tile.N * int64(sunlight.TileWidth)
		end := start + int64(tile.W)
		if start >= 0 && end <= int64(len(rt.entries)) {
			for i := start; i < end; i++ {
				data = sunlight.AppendTileLeaf(data, rt.entries[i])
			}
		} else {
			err = errors.New("tile entry range invalid")
		}
	} else {
		err = errors.New("tile is not a data tile")
	}
	return
}

func (rt *tileRoundTripper) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	rt.requests.Add(1)
	path := strings.TrimPrefix(req.URL.Path, "/")
	status := http.StatusOK
	var data []byte
	if path == "checkpoint" {
		data = rt.checkpoint
	} else if strings.HasPrefix(path, "tile/") {
		var tile tlog.Tile
		tile, err = sunlight.ParseTilePath(path)
		if err == nil {
			if tile.L == -1 {
				rt.dataTileCalls.Add(1)
				data, err = rt.dataTile(tile)
			} else if tile.L >= 0 {
				if tile.W < sunlight.TileWidth && !rt.partialHashTile[tile] {
					status = http.StatusNotFound
				} else {
					data, err = tlog.ReadTileData(tile, tlog.HashReaderFunc(rt.hashStore.readHashes))
				}
			} else {
				status = http.StatusNotFound
			}
		} else {
			status = http.StatusNotFound
			err = nil
		}
	} else {
		status = http.StatusNotFound
	}
	if err != nil {
		status = http.StatusNotFound
		data = nil
		err = nil
	}
	resp = &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(data)),
		Header:     make(http.Header),
	}
	return
}

func newTileTestStream(t testing.TB, count int) (*LogStream, *tileRoundTripper) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	cert := makeTestCertificate(t, now)
	entries := make([]*sunlight.LogEntry, count)
	recordHashes := make([]tlog.Hash, len(entries))
	for i := range entries {
		entries[i] = &sunlight.LogEntry{Certificate: cert, Timestamp: now.UnixMilli(), LeafIndex: int64(i)}
		recordHashes[i] = tlog.RecordHash(entries[i].MerkleTreeLeaf())
	}
	store, err := newTileHashStore(recordHashes)
	if err != nil {
		t.Fatalf("newTileHashStore: %v", err)
	}
	treeHash, err := tlog.TreeHash(int64(len(entries)), tlog.HashReaderFunc(store.readHashes))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	tree := tlog.Tree{N: int64(len(entries)), Hash: treeHash}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	checkpoint := mustSignedCheckpoint(t, "test-log", priv, tree)
	rt := &tileRoundTripper{
		entries:         entries,
		hashStore:       store,
		checkpoint:      checkpoint,
		partialHashTile: make(map[tlog.Tile]bool),
	}
	for _, tile := range tlog.NewTiles(sunlight.TileHeight, 0, tree.N) {
		if tile.W < sunlight.TileWidth {
			rt.partialHashTile[tile] = true
		}
	}
	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "https://example.test/",
		PublicKey:        priv.Public(),
		HTTPClient:       &http.Client{Transport: rt},
		UserAgent:        "certstream-test (+https://example.test)",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ls := &LogStream{
		LogOperator: &LogOperator{
			CertStream: &CertStream{},
		},
		headTile: client,
	}
	return ls, rt
}

func TestGetTileEntriesReturnsNextIndex(t *testing.T) {
	ls, _ := newTileTestStream(t, 3)
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		return true
	}
	next, wanted := ls.getTileEntries(t.Context(), 0, 2, false, handleFn, nil)
	if !wanted {
		t.Fatalf("wanted = false, want true")
	}
	if next != 3 {
		t.Fatalf("next = %d, want 3", next)
	}
}

func TestGetTileEntriesSingleGapReadsOneTile(t *testing.T) {
	ls, transport := newTileTestStream(t, 50*sunlight.TileWidth)
	const index = sunlight.TileWidth + 17
	var seen []int64
	var remaining atomic.Int64
	remaining.Store(1)
	handleFn := func(_ context.Context, _ time.Time, entry *LogEntry) bool {
		seen = append(seen, entry.LogIndex)
		return true
	}
	next, wanted := ls.getTileEntries(t.Context(), index, index, true, handleFn, &remaining)
	if next != index+1 || !wanted || len(seen) != 1 || seen[0] != index {
		t.Fatalf("next=%d wanted=%v seen=%v", next, wanted, seen)
	}
	if got := remaining.Load(); got != 0 {
		t.Fatalf("remaining=%d, want 0", got)
	}
	if got := transport.dataTileCalls.Load(); got != 1 {
		t.Fatalf("data tile requests=%d, want 1", got)
	}
}

func TestGetTileEntriesRangesOnPublishedTree(t *testing.T) {
	tests := []struct {
		name      string
		count     int
		start     int64
		end       int64
		wantTiles int64
	}{
		{"full tree", 50 * sunlight.TileWidth, 24*sunlight.TileWidth + 17, 28*sunlight.TileWidth + 16, 26},
		{"partial tip", 4*sunlight.TileWidth + 7, 4*sunlight.TileWidth - 3, 4*sunlight.TileWidth + 6, 2},
		{"before partial tip", 4*sunlight.TileWidth + 7, 2*sunlight.TileWidth + 7, 2*sunlight.TileWidth + 12, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls, transport := newTileTestStream(t, tt.count)
			var seen []int64
			handleFn := func(_ context.Context, _ time.Time, entry *LogEntry) bool {
				seen = append(seen, entry.LogIndex)
				return true
			}
			next, wanted := ls.getTileEntries(t.Context(), tt.start, tt.end, true, handleFn, nil)
			if !wanted || next != tt.end+1 || len(seen) != int(tt.end-tt.start+1) {
				t.Fatalf("next=%d wanted=%v entries=%d", next, wanted, len(seen))
			}
			for i, index := range seen {
				if index != tt.start+int64(i) {
					t.Fatalf("entry %d index=%d, want %d", i, index, tt.start+int64(i))
				}
			}
			if got := transport.dataTileCalls.Load(); got != tt.wantTiles {
				t.Fatalf("data tile requests=%d, want %d", got, tt.wantTiles)
			}
		})
	}
}

func TestGetTileEntriesUsesPublishedHashTiles(t *testing.T) {
	ls, _ := newTileTestStream(t, 50*sunlight.TileWidth)
	ls.backoff = newLogStreamBackoff(time.Millisecond, time.Millisecond, 2, false)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	start := int64(24*sunlight.TileWidth + 17)
	end := start + LogBatchSize - 1
	next, wanted := ls.getTileEntries(ctx, start, end, true,
		func(context.Context, time.Time, *LogEntry) bool { return true }, nil)
	if next != end+1 || !wanted {
		t.Fatalf("next=%d wanted=%v, want next=%d wanted=true", next, wanted, end+1)
	}
}

func TestGetTileEntriesReverseTraversalNoRefetch(t *testing.T) {
	const count = 50*sunlight.TileWidth + 7
	ls, transport := newTileTestStream(t, count)
	seen := make([]bool, count)
	handleFn := func(_ context.Context, _ time.Time, entry *LogEntry) bool {
		index := entry.LogIndex
		if index < 0 || index >= count || seen[index] {
			t.Fatalf("duplicate or invalid entry index %d", index)
		}
		seen[index] = true
		return true
	}
	for minIndex := int64(count); minIndex > 0; {
		start := reverseBackfillStart(minIndex, true)
		next, wanted := ls.getTileEntries(t.Context(), start, minIndex-1, true, handleFn, nil)
		if next != minIndex || !wanted {
			t.Fatalf("getTileEntries(%d, %d): next=%d wanted=%v", start, minIndex-1, next, wanted)
		}
		minIndex = start
	}
	for index, got := range seen {
		if !got {
			t.Fatalf("entry %d missing", index)
		}
	}
	if got := transport.dataTileCalls.Load(); got != 51 {
		t.Fatalf("data tile requests=%d, want 51", got)
	}
}

func TestGetTileEntriesWaitsForCheckpointIndex(t *testing.T) {
	ls, transport := newTileTestStream(t, 3)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ls.backoff = newLogStreamBackoff(time.Second, time.Second, 2, false)
	ls.backoff.sleepFn = func(context.Context, time.Duration) error {
		cancel()
		return ctx.Err()
	}
	called := false
	next, wanted := ls.getTileEntries(ctx, 3, 3, false, func(context.Context, time.Time, *LogEntry) bool {
		called = true
		return true
	}, nil)
	if next != 3 || wanted || called {
		t.Fatalf("next=%d wanted=%v called=%v", next, wanted, called)
	}
	if got := ls.errcount; got != 0 {
		t.Fatalf("stream errors=%d, want 0", got)
	}
	if got := transport.dataTileCalls.Load(); got != 0 {
		t.Fatalf("data tile requests=%d, want 0", got)
	}
}

func BenchmarkGetTileEntriesSingleGap(b *testing.B) {
	ls, transport := newTileTestStream(b, 50*sunlight.TileWidth)
	const index = sunlight.TileWidth + 17
	handleFn := func(context.Context, time.Time, *LogEntry) bool { return true }
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		next, wanted := ls.getTileEntries(b.Context(), index, index, false, handleFn, nil)
		if next != index+1 || !wanted {
			b.Fatalf("getTileEntries: next=%d wanted=%v", next, wanted)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(transport.requests.Load())/float64(b.N), "http-requests/op")
	b.ReportMetric(float64(transport.dataTileCalls.Load())/float64(b.N), "data-tiles/op")
}

func BenchmarkGetTileEntriesReverseTraversal(b *testing.B) {
	const count = 50 * sunlight.TileWidth
	ls, transport := newTileTestStream(b, count)
	handleFn := func(context.Context, time.Time, *LogEntry) bool { return true }
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for minIndex := int64(count); minIndex > 0; {
			start := reverseBackfillStart(minIndex, true)
			end := minIndex - 1
			next, wanted := ls.getTileEntries(b.Context(), start, end, true, handleFn, nil)
			if next != minIndex || !wanted {
				b.Fatalf("getTileEntries(%d, %d): next=%d wanted=%v", start, end, next, wanted)
			}
			minIndex = start
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(transport.requests.Load())/float64(b.N), "http-requests/op")
	b.ReportMetric(float64(transport.dataTileCalls.Load())/float64(b.N), "data-tiles/op")
}
