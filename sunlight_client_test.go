package certstream

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/torchwood"
	"github.com/google/certificate-transparency-go/loglist3"
)

func newTestTiledLog(t *testing.T) *loglist3.TiledLog {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return &loglist3.TiledLog{
		Key:           keyBytes,
		MonitoringURL: "https://example.com/ct",
	}
}

func TestNewSunlightClientCacheDir(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	client, err := newSunlightClient(newTestTiledLog(t), http.DefaultClient, nil, 1, cacheDir)
	if err != nil {
		t.Fatalf("newSunlightClient: %v", err)
	}
	if client == nil {
		t.Fatalf("newSunlightClient returned nil client")
	}
	if stat, err := os.Stat(cacheDir); err != nil {
		t.Fatalf("Stat cache dir: %v", err)
	} else if !stat.IsDir() {
		t.Fatalf("cache path is not a directory: %s", cacheDir)
	}
	if _, ok := client.TileReader().(*torchwood.PermanentCache); !ok {
		t.Fatalf("expected permanent cache tile reader")
	}
}

func TestNewSunlightClientCacheNone(t *testing.T) {
	client, err := newSunlightClient(newTestTiledLog(t), http.DefaultClient, nil, 1, "none")
	if err != nil {
		t.Fatalf("newSunlightClient: %v", err)
	}
	if client == nil {
		t.Fatalf("newSunlightClient returned nil client")
	}
	if _, ok := client.TileReader().(*torchwood.PermanentCache); ok {
		t.Fatalf("unexpected permanent cache tile reader for disabled cache")
	}
}
