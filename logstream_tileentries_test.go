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
	"testing"
	"time"

	"filippo.io/sunlight"
	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type tileHashStore struct {
	hashes map[int64]tlog.Hash
}

type tileRoundTripper struct {
	entries    []*sunlight.LogEntry
	hashStore  *tileHashStore
	checkpoint []byte
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

func mustSignedCheckpoint(t *testing.T, name string, priv *ecdsa.PrivateKey, tree tlog.Tree) (noteBytes []byte) {
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
						Text: sunlight.FormatCheckpoint(sunlight.Checkpoint{
							Origin: name,
							Tree:   tree,
						}),
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
				data, err = rt.dataTile(tile)
			} else if tile.L >= 0 {
				data, err = tlog.ReadTileData(tile, tlog.HashReaderFunc(rt.hashStore.readHashes))
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

func TestGetTileEntriesReturnsNextIndex(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	cert := makeTestCertificate(t, now)
	entries := []*sunlight.LogEntry{
		{
			Certificate: cert,
			Timestamp:   now.UnixMilli(),
			LeafIndex:   0,
		},
		{
			Certificate: cert,
			Timestamp:   now.UnixMilli(),
			LeafIndex:   1,
		},
		{
			Certificate: cert,
			Timestamp:   now.UnixMilli(),
			LeafIndex:   2,
		},
	}
	recordHashes := make([]tlog.Hash, len(entries))
	for i, entry := range entries {
		recordHashes[i] = tlog.RecordHash(entry.MerkleTreeLeaf())
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
		entries:    entries,
		hashStore:  store,
		checkpoint: checkpoint,
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
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		return true
	}
	next, wanted := ls.getTileEntries(context.Background(), 0, 2, false, handleFn, nil)
	if !wanted {
		t.Fatalf("wanted = false, want true")
	}
	if next != 3 {
		t.Fatalf("next = %d, want 3", next)
	}
}
