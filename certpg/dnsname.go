package certpg

type Dnsname struct {
	CertID  int64
	DNSName string
	Idna    bool
	Valid   bool
	Issuer  string
	Subject string
	Crtsh   string
}
