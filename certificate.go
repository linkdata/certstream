package certstream

import (
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

type Certificate struct {
	PreCert   bool
	Seen      time.Time
	Signature []byte
	*x509.Certificate
}
