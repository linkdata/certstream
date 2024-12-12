package certpg

import (
	"time"
)

type Certificate struct {
	Id         int64
	NotBefore  time.Time
	NotAfter   time.Time
	CommonName string
	SubjectID  int
	IssuerID   int
	Sha256     []byte
	PreCert    bool
}

func ScanCertificate(row Scanner, cert *Certificate) (err error) {
	return row.Scan(
		&cert.Id,
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.CommonName,
		&cert.SubjectID,
		&cert.IssuerID,
		&cert.Sha256,
		&cert.PreCert,
	)
}
