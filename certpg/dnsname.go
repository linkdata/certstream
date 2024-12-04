package certpg

import "time"

type Dnsname struct {
	CertID    int64
	DNSName   string
	NotBefore time.Time
	Idna      bool
	Valid     bool
	Issuer    string
	Subject   string
	Crtsh     string
}
