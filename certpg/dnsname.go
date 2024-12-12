package certpg

type Dnsname struct {
	Dnsname string
	CertID  int64
}

func ScanDnsname(row Scanner, p *Dnsname) error {
	return row.Scan(
		&p.Dnsname,
		&p.CertID,
	)
}
