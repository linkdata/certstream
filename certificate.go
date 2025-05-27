package certstream

import (
	"slices"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

type Certificate struct {
	PreCert   bool
	Seen      time.Time
	Signature []byte
	*x509.Certificate
}

func (c *Certificate) GetCommonName() (s string) {
	if s = c.Subject.CommonName; s == "" {
		if len(c.DNSNames) > 0 {
			names := slices.Clone(c.DNSNames)
			slices.Sort(names)
			s = c.DNSNames[0]
		}
	}
	return
}
