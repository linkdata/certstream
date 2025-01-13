package certstream

type PgDnsname struct {
	Dnsname string
	CertID  int64
}

func ScanDnsname(row Scanner, p *PgDnsname) error {
	return row.Scan(
		&p.Dnsname,
		&p.CertID,
	)
}
