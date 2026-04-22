package certstream

import (
	"time"
)

type PgView struct {
	CertID              int64
	FQDN                string
	CommonName          string
	NotBefore           time.Time
	NotAfter            time.Time
	Since               time.Time
	PreCert             bool
	Sha256              []byte
	IssuerOrganization  string
	IssuerProvince      string
	IssuerCountry       string
	SubjectOrganization string
	SubjectProvince     string
	SubjectCountry      string
	Wild                bool
	WWW                 int
	Domain              string
	Tld                 string
}

func ScanView(row Scanner, v *PgView) (err error) {
	return row.Scan(
		&v.CertID,
		&v.FQDN,
		&v.CommonName,
		&v.NotBefore,
		&v.NotAfter,
		&v.Since,
		&v.PreCert,
		&v.Sha256,
		&v.IssuerOrganization,
		&v.IssuerProvince,
		&v.IssuerCountry,
		&v.SubjectOrganization,
		&v.SubjectProvince,
		&v.SubjectCountry,
		&v.Wild,
		&v.WWW,
		&v.Domain,
		&v.Tld,
	)
}
