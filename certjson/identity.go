package certjson

import (
	"strings"

	"github.com/google/certificate-transparency-go/x509/pkix"
)

type Identity struct {
	Country            string `json:",omitempty"`
	Organization       string `json:",omitempty"`
	OrganizationalUnit string `json:",omitempty"`
	Locality           string `json:",omitempty"`
	Province           string `json:",omitempty"`
	StreetAddress      string `json:",omitempty"`
	PostalCode         string `json:",omitempty"`
	SerialNumber       string `json:",omitempty"`
	CommonName         string `json:",omitempty"`
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

func (id *Identity) Fill(name *pkix.Name) {
	if name != nil {
		id.Country = join(name.Country)
		id.Organization = join(name.Organization)
		id.OrganizationalUnit = join(name.OrganizationalUnit)
		id.Locality = join(name.Locality)
		id.Province = join(name.Province)
		id.StreetAddress = join(name.StreetAddress)
		id.PostalCode = join(name.PostalCode)
		id.SerialNumber = strings.TrimSpace(name.SerialNumber)
		id.CommonName = strings.TrimSpace(name.CommonName)
	}
}
