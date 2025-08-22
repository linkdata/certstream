package certstream

import (
	"testing"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestJsonCertificateSetCommonName(t *testing.T) {
	// Subject CN present → used
	x := &x509.Certificate{Subject: pkix.Name{CommonName: "cn.example"}}
	j := NewJSONCertificate(&Certificate{Certificate: x})
	j.SetCommonName()
	if j.CommonName != "cn.example" {
		t.Fatalf("CommonName = %q, want %q", j.CommonName, "cn.example")
	}

	// No Subject CN, fallback to first SAN
	x = &x509.Certificate{DNSNames: []string{"a.example", "b.example"}}
	j = NewJSONCertificate(&Certificate{Certificate: x})
	j.SetCommonName()
	if j.CommonName != "a.example" {
		t.Fatalf("CommonName = %q, want %q", j.CommonName, "a.example")
	}

	// No names at all → empty
	x = &x509.Certificate{}
	j = NewJSONCertificate(&Certificate{Certificate: x})
	j.SetCommonName()
	if j.CommonName != "" {
		t.Fatalf("CommonName = %q, want empty", j.CommonName)
	}
}
