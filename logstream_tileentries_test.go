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
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/transparency-dev/formats/log"
	formatnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/ctonly"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

type tileRoundTripper struct {
	entryBundle []byte
	checkpoint  []byte
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

func mustSignedCheckpoint(t *testing.T, name string, verifier note.Verifier, priv *ecdsa.PrivateKey, treeSize uint64, treeHash []byte) (noteBytes []byte) {
	t.Helper()
	var err error
	timestamp := uint64(time.Now().UnixMilli())
	sth := ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       treeSize,
		Timestamp:      timestamp,
		SHA256RootHash: ct.SHA256Hash(treeHash),
	}
	var sthInput []byte
	if sthInput, err = ct.SerializeSTHSignatureInput(sth); err == nil {
		var treeSig []byte
		if treeSig, err = signTreeHead(priv, sthInput); err == nil {
			var sig []byte
			if sig, err = noteSignature(timestamp, treeSig); err == nil {
				signer := &injectedSigner{v: verifier, sig: sig}
				noteBytes, err = note.Sign(&note.Note{
					Text: string(log.Checkpoint{
						Origin: name,
						Size:   treeSize,
						Hash:   treeHash,
					}.Marshal()),
				}, signer)
			}
		}
	}
	if err != nil {
		t.Fatalf("checkpoint sign failed: %v", err)
	}
	return
}

func mustMarshalPKIXPublicKey(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

func appendEntryBundle(bundle []byte, entryData []byte) ([]byte, error) {
	if len(entryData) > math.MaxUint16 {
		return nil, errors.New("entry too large for bundle")
	}
	length := uint16(len(entryData))
	bundle = append(bundle, byte(length>>8), byte(length))
	bundle = append(bundle, entryData...)
	return bundle, nil
}

func (rt *tileRoundTripper) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	path := strings.TrimPrefix(req.URL.Path, "/")
	status := http.StatusOK
	var data []byte
	if path == "checkpoint" {
		data = rt.checkpoint
	} else if strings.HasPrefix(path, "tile/entries/") {
		entryPath := strings.TrimPrefix(path, "tile/entries/")
		index, _, parseErr := layout.ParseTileIndexPartial(entryPath)
		if parseErr != nil {
			status = http.StatusNotFound
		} else if index == 0 {
			data = rt.entryBundle
		} else {
			status = http.StatusNotFound
		}
	} else {
		status = http.StatusNotFound
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
	entries := []*ctonly.Entry{
		{
			Certificate: cert,
			Timestamp:   uint64(now.UnixMilli()),
		},
		{
			Certificate: cert,
			Timestamp:   uint64(now.UnixMilli()),
		},
		{
			Certificate: cert,
			Timestamp:   uint64(now.UnixMilli()),
		},
	}
	tree := testonly.New(rfc6962.DefaultHasher)
	entryBundle := []byte{}
	for i, entry := range entries {
		tree.AppendData(entry.MerkleTreeLeaf(uint64(i)))
		var bundleErr error
		entryBundle, bundleErr = appendEntryBundle(entryBundle, entry.LeafData(uint64(i)))
		if bundleErr != nil {
			t.Fatalf("appendEntryBundle: %v", bundleErr)
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	vkey, err := formatnote.RFC6962VerifierString("https://example.test/", &priv.PublicKey)
	if err != nil {
		t.Fatalf("RFC6962VerifierString: %v", err)
	}
	verifier, err := formatnote.NewRFC6962Verifier(vkey)
	if err != nil {
		t.Fatalf("NewRFC6962Verifier: %v", err)
	}
	checkpoint := mustSignedCheckpoint(t, "example.test", verifier, priv, tree.Size(), tree.Hash())
	rt := &tileRoundTripper{
		entryBundle: entryBundle,
		checkpoint:  checkpoint,
	}
	client, err := newTesseraClient(&loglist3.TiledLog{
		MonitoringURL: "https://example.test/",
		Key:           mustMarshalPKIXPublicKey(t, &priv.PublicKey),
	}, &http.Client{Transport: rt})
	if err != nil {
		t.Fatalf("newTesseraClient: %v", err)
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
	wanted, next, err := ls.getTileEntries(t.Context(), client, 0, 2, false, handleFn, nil)
	if err != nil {
		t.Fatalf("getTileEntries: %v", err)
	}
	if !wanted {
		t.Fatalf("wanted = false, want true")
	}
	if next != 3 {
		t.Fatalf("next = %d, want 3", next)
	}
}
