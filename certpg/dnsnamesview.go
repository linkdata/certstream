package certpg

import (
	"time"
)

type DnsnamesView struct {
	CertID    int64
	DNSName   string
	NotBefore time.Time
	Idna      bool
	Valid     bool
	PreCert   bool
	Issuer    string
	Subject   string
	Crtsh     string
}

func ScanDnsnamesView(row Scanner, dnsname *DnsnamesView) (err error) {
	return row.Scan(
		&dnsname.CertID,
		&dnsname.DNSName,
		&dnsname.NotBefore,
		&dnsname.Idna,
		&dnsname.Valid,
		&dnsname.PreCert,
		&dnsname.Issuer,
		&dnsname.Subject,
		&dnsname.Crtsh,
	)
}
