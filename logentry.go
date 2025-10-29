package certstream

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/net/idna"
)

type LogEntry struct {
	*LogStream
	Err          error           // error from RawLogEntryFromLeaf or ToLogEntry, or nil
	RawLogEntry  *ct.RawLogEntry // may be nil in case of error
	*ct.LogEntry                 // may be nil in case of error
	Id           int64           // database id, if available
	Historical   bool            // true if the entry is from gap or backfilling
}

func (le *LogEntry) appendJSON(b []byte) []byte {
	if cert := le.Cert(); cert != nil {
		logindex := le.Index()
		var dnsnames []string
		for _, dnsname := range cert.DNSNames {
			dnsname = strings.ToLower(dnsname)
			if uniname, err := idna.ToUnicode(dnsname); err == nil && uniname != dnsname {
				ok := true
				for _, r := range uniname {
					ok = ok && strconv.IsPrint(r)
				}
				if ok {
					dnsname = uniname
				}
			}
			dnsnames = append(dnsnames, dnsname)
		}

		var ipaddrs []string
		for _, ip := range cert.IPAddresses {
			ipaddrs = append(ipaddrs, ip.String())
		}

		var emails []string
		for _, email := range cert.EmailAddresses {
			emails = append(emails, strings.ReplaceAll(email, " ", "_"))
		}

		var uris []string
		for _, uri := range cert.URIs {
			uris = append(uris, strings.ReplaceAll(uri.String(), " ", "%20"))
		}

		b = append(b, `{`...)
		b = append(b, `"iss_org":`...)
		b = strconv.AppendQuote(b, strings.Join(cert.Issuer.Organization, ","))
		b = append(b, `,"iss_prov":`...)
		b = strconv.AppendQuote(b, strings.Join(cert.Issuer.Province, ","))
		b = append(b, `,"iss_country":`...)
		b = strconv.AppendQuote(b, strings.Join(cert.Issuer.Country, ","))
		b = append(b, `,"sub_org":`...)
		b = strconv.AppendQuote(b, strings.Join(cert.Subject.Organization, ","))
		b = append(b, `,"sub_prov":`...)
		b = strconv.AppendQuote(b, strings.Join(cert.Subject.Province, ","))
		b = append(b, `,"sub_country":`...)
		b = strconv.AppendQuote(b, strings.Join(cert.Subject.Country, ","))
		b = append(b, `,"notbefore":"`...)
		b = append(b, cert.NotBefore.UTC().Format(time.RFC3339)...)
		b = append(b, `","notafter":"`...)
		b = append(b, cert.NotAfter.UTC().Format(time.RFC3339)...)
		b = append(b, `","commonname":`...)
		b = strconv.AppendQuote(b, cert.GetCommonName())
		b = append(b, `,"sha256_hex":"`...)
		b = append(b, hex.EncodeToString(cert.Signature)...)
		b = append(b, `","precert":`...)
		b = strconv.AppendBool(b, cert.PreCert)
		b = append(b, `,"seen":"`...)
		b = append(b, cert.Seen.UTC().Format(time.RFC3339)...)
		b = append(b, `","stream":`...)
		b = strconv.AppendInt(b, int64(le.LogStream.Id), 10)
		b = append(b, `,"logindex":`...)
		b = strconv.AppendInt(b, logindex, 10)
		b = append(b, `,"dnsnames":`...)
		b = strconv.AppendQuote(b, strings.Join(dnsnames, " "))
		b = append(b, `,"ipaddrs":`...)
		b = strconv.AppendQuote(b, strings.Join(ipaddrs, " "))
		b = append(b, `,"emails":`...)
		b = strconv.AppendQuote(b, strings.Join(emails, " "))
		b = append(b, `,"uris":`...)
		b = strconv.AppendQuote(b, strings.Join(uris, " "))
		b = append(b, `}`...)
	} else {
		b = append(b, `{}`...)
	}
	return b
}

func (le *LogEntry) String() (s string) {
	var b []byte
	b = append(b, "LogEntry{"...)
	if le != nil {
		if le.LogStream != nil {
			if le.Operator != nil {
				b = strconv.AppendQuote(b, le.Operator.Name)
				b = append(b, ", "...)
			}
			if le.Log != nil {
				b = strconv.AppendQuote(b, le.Log.URL)
				b = append(b, ", "...)
			}
		}
		b = strconv.AppendInt(b, le.Index(), 10)
		if le.Err != nil {
			b = append(b, ", "...)
			b = strconv.AppendQuote(b, le.Err.Error())
		}
	}
	b = append(b, '}')
	return string(b)
}

// Cert returns the Certificate given a LogEntry or nil.
func (le *LogEntry) Cert() (crt *Certificate) {
	if le != nil && le.LogEntry != nil {
		var cert *x509.Certificate
		var precert bool
		if cert = le.LogEntry.X509Cert; cert == nil {
			if le.LogEntry.Precert != nil {
				precert = true
				cert = le.LogEntry.Precert.TBSCertificate
			}
		}
		if cert != nil {
			crt = &Certificate{
				PreCert:     precert,
				Certificate: cert,
			}
			if le.RawLogEntry != nil {
				shasig := sha256.Sum256(le.RawLogEntry.Cert.Data)
				crt.Signature = shasig[:]
				tse := int64(le.RawLogEntry.Leaf.TimestampedEntry.Timestamp) //#nosec G115
				crt.Seen = time.UnixMilli(tse).UTC()
			} else {
				shasig := sha256.Sum256(cert.RawTBSCertificate)
				crt.Signature = shasig[:]
				crt.Seen = time.Now().UTC()
			}
		}
	}
	return
}

// Index returns the log index or -1 if none is available.
func (le *LogEntry) Index() (index int64) {
	index = -1
	if le.RawLogEntry != nil {
		index = le.RawLogEntry.Index
	}
	return
}
