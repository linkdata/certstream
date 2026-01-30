package certstream

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

type countingTransport struct {
	count atomic.Int64
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.count.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("ok")),
	}, nil
}

func (t *countingTransport) Count() int64 {
	return t.count.Load()
}

func makeTestCertificate(t *testing.T, now time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.test",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestMakeTileLogEntryParsesCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	der := makeTestCertificate(t, now)
	entry := &tileEntry{
		Certificate: der,
		Timestamp:   uint64(now.UnixMilli()),
	}
	ls := &LogStream{}
	le := ls.makeTileLogEntry(42, entry, false)
	if le == nil {
		t.Fatalf("makeTileLogEntry returned nil")
	}
	if le.PreCert {
		t.Fatalf("makeTileLogEntry marked entry as precert")
	}
	if le.Certificate == nil {
		t.Fatalf("makeTileLogEntry did not parse certificate")
	}
	if !le.Seen.Equal(now) {
		t.Fatalf("Seen = %v, want %v", le.Seen, now)
	}
	if le.LogIndex != 42 {
		t.Fatalf("LogIndex = %d, want 42", le.LogIndex)
	}
	if got, want := le.Signature, sha256.Sum256(der); len(got) == 0 || !bytes.Equal(got, want[:]) {
		t.Fatalf("Signature mismatch")
	}
}

func TestMakeTiledStreamUsesDialers(t *testing.T) {
	headTransport := &countingTransport{}
	tailTransport := &countingTransport{}

	cs := &CertStream{
		Config: Config{
			Concurrency: 2,
		},
		HeadClient: &http.Client{
			Transport: headTransport,
		},
		TailClient: &http.Client{
			Transport: tailTransport,
		},
	}
	op := &loglist3.Operator{
		Name:  "Test",
		Email: []string{"test@example.com"},
	}
	lo := &LogOperator{
		CertStream: cs,
		operator:   op,
		Domain:     "example.com",
		streams:    map[string]*LogStream{},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	tiledLog := &loglist3.TiledLog{
		MonitoringURL: "https://example.test/",
		Key:           keyDER,
	}

	ls, err := lo.makeTiledStream(tiledLog)
	if err != nil {
		t.Fatalf("makeTiledStream: %v", err)
	}
	if ls.URL() != tiledLog.MonitoringURL {
		t.Fatalf("URL() = %q, want %q", ls.URL(), tiledLog.MonitoringURL)
	}
	if ls.headTile == nil || ls.tailTile == nil {
		t.Fatalf("expected head and tail tessera clients")
	}

	ctx := t.Context()
	if _, err := ls.headTile.fetch(ctx, "checkpoint"); err != nil {
		t.Fatalf("head checkpoint: %v", err)
	}
	if headTransport.Count() == 0 {
		t.Fatalf("head transport not used")
	}
	if tailTransport.Count() != 0 {
		t.Fatalf("tail transport used for head client")
	}
	if _, err := ls.tailTile.fetch(ctx, "checkpoint"); err != nil {
		t.Fatalf("tail checkpoint: %v", err)
	}
	if tailTransport.Count() == 0 {
		t.Fatalf("tail transport not used")
	}
}
