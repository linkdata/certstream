package certstream

import (
	"time"
)

type PgDnsnamesView struct {
	CertID    int64
	FQDN      string
	NotBefore time.Time
	Idna      bool
	Valid     bool
	PreCert   bool
	Issuer    string
	Subject   string
	Crtsh     string
	Domain    string
	Tld       string
}

func ScanDnsnamesView(row Scanner, dnsname *PgDnsnamesView) (err error) {
	return row.Scan(
		&dnsname.CertID,
		&dnsname.FQDN,
		&dnsname.NotBefore,
		&dnsname.Idna,
		&dnsname.Valid,
		&dnsname.PreCert,
		&dnsname.Issuer,
		&dnsname.Subject,
		&dnsname.Crtsh,
		&dnsname.Domain,
		&dnsname.Tld,
	)
}
