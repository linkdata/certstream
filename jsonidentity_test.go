package certstream

import (
	"testing"

	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestJsonIdentityFill(t *testing.T) {
	name := &pkix.Name{
		CommonName:   "Alice",
		Organization: []string{"Acme Corp"},
		Country:      []string{"SE"},
		Province:     []string{"Stockholm"},
	}
	var id JsonIdentity
	id.fill(name)

	if id.CommonName != "Alice" {
		t.Fatalf("CommonName = %q, want %q", id.CommonName, "Alice")
	}
	if id.Organization != "Acme Corp" {
		t.Fatalf("Organization = %q, want %q", id.Organization, "Acme Corp")
	}
	if id.Country != "SE" {
		t.Fatalf("Country = %q, want %q", id.Country, "SE")
	}
	if id.Province != "Stockholm" {
		t.Fatalf("Province = %q, want %q", id.Province, "Stockholm")
	}
}
