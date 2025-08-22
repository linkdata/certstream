package certstream

import (
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestCertificateGetCommonName_PrefersSubject(t *testing.T) {
	x := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "cn.example"},
		DNSNames:  []string{"a.example", "b.example"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	c := &Certificate{Certificate: x}
	if got := c.GetCommonName(); got != "cn.example" {
		t.Fatalf("GetCommonName() = %q, want %q", got, "cn.example")
	}
}

func TestCertificateGetCommonName_FallbackToSAN(t *testing.T) {
	x := &x509.Certificate{
		DNSNames: []string{"a.example", "b.example"},
	}
	c := &Certificate{Certificate: x}
	if got := c.GetCommonName(); got != "a.example" {
		t.Fatalf("GetCommonName() = %q, want %q", got, "a.example")
	}
}

func TestCertificateGetCommonName_EmptyWhenNoNames(t *testing.T) {
	c := &Certificate{Certificate: &x509.Certificate{}}
	if got := c.GetCommonName(); got != "" {
		t.Fatalf("GetCommonName() = %q, want empty", got)
	}
}
