package certstream

import (
	"time"
)

type PgCertificate struct {
	Id         int64
	NotBefore  time.Time
	NotAfter   time.Time
	CommonName string
	SubjectID  int
	IssuerID   int
	Sha256     []byte
	PreCert    bool
	Since      time.Time
}

func ScanCertificate(row Scanner, cert *PgCertificate) (err error) {
	var p_since *time.Time
	if err = row.Scan(
		&cert.Id,
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.CommonName,
		&cert.SubjectID,
		&cert.IssuerID,
		&cert.Sha256,
		&cert.PreCert,
		&p_since,
	); err == nil {
		if p_since != nil {
			cert.Since = *p_since
		}
	}
	return
}
