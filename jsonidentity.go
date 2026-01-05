package certstream

import (
	"strings"

	"github.com/google/certificate-transparency-go/x509/pkix"
)

type JsonIdentity struct {
	ID           int    `json:",omitempty"`
	Country      string `json:",omitempty"`
	Organization string `json:",omitempty"`
	Province     string `json:",omitempty"`
	CommonName   string `json:",omitempty"`
}

func join(l []string) string {
	var b []byte
	for _, s := range l {
		if s = strings.TrimSpace(s); s != "" {
			if len(b) > 0 {
				b = append(b, ' ')
			}
			b = append(b, s...)
		}
	}
	return string(b)
}

func (id *JsonIdentity) fill(name *pkix.Name) {
	if name != nil {
		id.Country = join(name.Country)
		id.Organization = join(name.Organization)
		id.Province = join(name.Province)
		id.CommonName = strings.TrimSpace(name.CommonName)
	}
}
