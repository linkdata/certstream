package certstream

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

func TestParseBadCertMetadata(t *testing.T) {
	// TrustAsia HETU2027 entry 8925345 has mismatched inner and outer signature identifiers.
	// Source: https://hetu2027.trustasia.com/hetu2027/ct/v1/get-entries?start=8925345&end=8925345
	raw, err := os.ReadFile("testdata/hetu2027-8925345.der")
	if err != nil {
		t.Fatal(err)
	}
	var outer, tbs asn1.RawValue
	if _, err = asn1.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	if _, err = asn1.Unmarshal(outer.Bytes, &tbs); err != nil {
		t.Fatal(err)
	}
	want := badCertMetadata{
		commonName: "Encryption Everywhere DV TLS CA - G1",
		subject:    [3]string{"DigiCert Inc", "", "US"},
		issuer:     [3]string{"DigiCert Inc", "", "US"},
	}
	for _, tt := range []struct {
		name string
		raw  []byte
		want badCertMetadata
	}{
		{name: "certificate", raw: raw, want: want},
		{name: "certificate with trailing data", raw: append(append([]byte(nil), raw...), 0), want: want},
		{name: "TBS certificate", raw: tbs.FullBytes, want: want},
		{name: "unreadable", raw: []byte{0x30, 0x00}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseBadCertMetadata(tt.raw); got != tt.want {
				t.Fatalf("metadata = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBadCertText(t *testing.T) {
	if got := badCertText("a\x00b\xffc"); got != "abc" {
		t.Fatalf("badCertText = %q, want %q", got, "abc")
	}
}

func TestParseBadCertMetadataWithMalformedExtension(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "example.test",
			Organization: []string{"Acme"},
			Country:      []string{"SE"},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 15},
			Value: []byte{0x04, 0x00}, // invalid KeyUsage BIT STRING
		}},
	}
	raw, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if cert, parseErr := x509.ParseCertificate(raw); cert != nil || parseErr == nil {
		t.Fatalf("certificate = (parsed %v, err %v), want parse failure", cert != nil, parseErr)
	}
	want := badCertMetadata{
		commonName: "example.test",
		subject:    [3]string{"Acme", "", "SE"},
		issuer:     [3]string{"Acme", "", "SE"},
	}
	if got := parseBadCertMetadata(raw); got != want {
		t.Fatalf("metadata = %+v, want %+v", got, want)
	}
}

func TestMakeLogEntryWithBadExtraData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	x509Leaf := makeTestLeafEntry(t, now)
	var parsed ct.MerkleTreeLeaf
	if rest, err := tls.Unmarshal(x509Leaf.LeafInput, &parsed); err != nil || len(rest) != 0 {
		t.Fatalf("parse leaf input: rest length %d, err %v", len(rest), err)
	}
	cert, err := x509.ParseCertificate(parsed.TimestampedEntry.X509Entry.Data)
	if err != nil {
		t.Fatal(err)
	}
	precertLeaf, err := tls.Marshal(ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:    uint64(now.UnixMilli()),
			EntryType:    ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{TBSCertificate: cert.RawTBSCertificate},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name       string
		leaf       ct.LeafEntry
		raw        []byte
		wantParsed bool
	}{
		{name: "X509", leaf: x509Leaf, raw: parsed.TimestampedEntry.X509Entry.Data, wantParsed: true},
		{name: "precertificate", leaf: ct.LeafEntry{LeafInput: precertLeaf}, raw: cert.RawTBSCertificate},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.leaf.ExtraData = []byte{0xff}
			le := (&LogStream{}).makeLogEntry(1, tt.leaf, false)
			if le.Err == nil || (le.Certificate != nil) != tt.wantParsed || !le.Seen.Equal(now) {
				t.Fatalf("entry = (err %v, parsed %v, seen %v), want parsed %v and timestamp %v", le.Err, le.Certificate != nil, le.Seen, tt.wantParsed, now)
			}
			if tt.wantParsed && le.rawCert != nil || !tt.wantParsed && !bytes.Equal(le.rawCert, tt.raw) {
				t.Fatalf("raw certificate = %x, want parsed %v or raw %x", le.rawCert, tt.wantParsed, tt.raw)
			}
		})
	}
}
