package certstream

import (
	"strings"
	"testing"
)

func requireContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected to find %q", needle)
	}
}

func requireNotContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Fatalf("did not expect to find %q", needle)
	}
}

func TestCreateSchemaDomainPrimaryKey(t *testing.T) {
	requireContains(t, CreateSchema, "PRIMARY KEY (cert, wild, www, domain, tld)")
	requireNotContains(t, CreateSchema, "CERTDB_domain_cert_idx")
}

func TestDomainInsertConflictHandling(t *testing.T) {
	requireContains(t, FuncAttachMetadata, "ON CONFLICT (cert, wild, www, domain, tld) DO NOTHING")
	requireContains(t, FuncIngestBatch, "ON CONFLICT (cert, wild, www, domain, tld) DO NOTHING")
}

func TestEnsureDomainPKMigration(t *testing.T) {
	requireContains(t, FuncEnsureDomainPK, "CERTDB_ensure_domain_pk")
	requireContains(t, FuncEnsureDomainPK, "ADD PRIMARY KEY (cert, wild, www, domain, tld)")
	requireContains(t, FuncEnsureDomainPK, "DROP INDEX IF EXISTS CERTDB_domain_cert_idx")
}
