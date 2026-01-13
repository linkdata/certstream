package certstream_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

type splitDomainResult struct {
	wild   bool
	www    int16
	domain string
	tld    string
}

type splitDomainCase struct {
	fqdn string
	want splitDomainResult
}

func fetchSplitDomain(ctx context.Context, conn *pgx.Conn, fqdn string) (res splitDomainResult, err error) {
	if conn != nil {
		err = conn.QueryRow(ctx,
			"SELECT (r).wild, (r).www, (r).domain, (r).tld FROM CERTDB_split_domain($1) AS r;",
			fqdn).Scan(&res.wild, &res.www, &res.domain, &res.tld)
	}
	return
}

func TestSplitDomainCases(t *testing.T) {
	t.Parallel()

	ctx, conn, _ := setupIngestBatchTest(t)
	cases := []splitDomainCase{
		{
			fqdn: "example.com",
			want: splitDomainResult{wild: false, www: 0, domain: "example", tld: "com"},
		},
		{
			fqdn: "www.example.com",
			want: splitDomainResult{wild: false, www: 1, domain: "example", tld: "com"},
		},
		{
			fqdn: "www.www.example.com",
			want: splitDomainResult{wild: false, www: 2, domain: "example", tld: "com"},
		},
		{
			fqdn: "*.example.com",
			want: splitDomainResult{wild: true, www: 0, domain: "example", tld: "com"},
		},
		{
			fqdn: "*.www.example.com",
			want: splitDomainResult{wild: true, www: 1, domain: "example", tld: "com"},
		},
		{
			fqdn: "www.com",
			want: splitDomainResult{wild: false, www: 0, domain: "www", tld: "com"},
		},
		{
			fqdn: "www.www.com",
			want: splitDomainResult{wild: false, www: 1, domain: "www", tld: "com"},
		},
		{
			fqdn: "www.www.example.co.uk",
			want: splitDomainResult{wild: false, www: 2, domain: "example.co", tld: "uk"},
		},
		{
			fqdn: "example.com.",
			want: splitDomainResult{wild: false, www: 0, domain: "example.com", tld: ""},
		},
		{
			fqdn: "",
			want: splitDomainResult{wild: false, www: 0, domain: "", tld: ""},
		},
		{
			fqdn: "*",
			want: splitDomainResult{wild: true, www: 0, domain: "", tld: "*"},
		},
	}

	for _, tc := range cases {
		var got splitDomainResult
		var err error
		if got, err = fetchSplitDomain(ctx, conn, tc.fqdn); err != nil {
			t.Fatalf("split domain %q failed: %v", tc.fqdn, err)
		} else if got.wild != tc.want.wild {
			t.Fatalf("split domain %q wild = %v, want %v", tc.fqdn, got.wild, tc.want.wild)
		} else if got.www != tc.want.www {
			t.Fatalf("split domain %q www = %d, want %d", tc.fqdn, got.www, tc.want.www)
		} else if got.domain != tc.want.domain {
			t.Fatalf("split domain %q domain = %q, want %q", tc.fqdn, got.domain, tc.want.domain)
		} else if got.tld != tc.want.tld {
			t.Fatalf("split domain %q tld = %q, want %q", tc.fqdn, got.tld, tc.want.tld)
		}
	}
}
