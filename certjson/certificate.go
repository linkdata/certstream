package certjson

import (
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/linkdata/certstream"
	"golang.org/x/net/idna"
)

type Certificate struct {
	PreCert        bool      `json:",omitempty"`
	Signature      []byte    `json:",omitempty"` // SHA256 signature, searchable on crt.sh
	Issuer         Identity  `json:",omitempty"`
	Subject        Identity  `json:",omitempty"`
	DNSNames       []string  `json:",omitempty"`
	EmailAddresses []string  `json:",omitempty"`
	IPAddresses    []string  `json:",omitempty"`
	URIs           []string  `json:",omitempty"`
	NotBefore      time.Time `json:",omitempty"`
	NotAfter       time.Time `json:",omitempty"`
}

func New(le *certstream.LogEntry) (jsoncert *Certificate) {
	if cert := le.Cert(); cert != nil {
		jsoncert = &Certificate{
			PreCert:   le.IsPreCert(),
			Signature: le.Signature(),
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
		}
		jsoncert.Issuer.Fill(&cert.Issuer)
		jsoncert.Subject.Fill(&cert.Subject)

		for _, dnsname := range cert.DNSNames {
			dnsname = strings.ToLower(dnsname)
			if uniname, err := idna.ToUnicode(dnsname); err == nil && uniname != dnsname {
				jsoncert.DNSNames = append(jsoncert.DNSNames, uniname)
			} else {
				jsoncert.DNSNames = append(jsoncert.DNSNames, dnsname)
			}
		}
		sort.Strings(jsoncert.DNSNames)

		for _, ip := range cert.IPAddresses {
			jsoncert.IPAddresses = append(jsoncert.IPAddresses, ip.String())
		}
		sort.Strings(jsoncert.IPAddresses)

		for _, email := range cert.EmailAddresses {
			if m, e := mail.ParseAddress(email); e == nil {
				email = m.Address
			}
			jsoncert.EmailAddresses = append(jsoncert.EmailAddresses, email)
		}
		sort.Strings(jsoncert.EmailAddresses)

		for _, u := range cert.URIs {
			jsoncert.URIs = append(jsoncert.URIs, u.String())
		}
		sort.Strings(jsoncert.URIs)
	}
	return
}
