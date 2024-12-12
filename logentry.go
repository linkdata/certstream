package certstream

import (
	"crypto/sha256"
	"strconv"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

type LogEntry struct {
	*LogStream
	Err          error           // error from RawLogEntryFromLeaf or ToLogEntry, or nil
	RawLogEntry  *ct.RawLogEntry // may be nil in case of error
	*ct.LogEntry                 // may be nil in case of error
	Id           int64           // database id, if available
	Historical   bool            // true if the entry is from gap or backfilling
}

func (le *LogEntry) String() (s string) {
	var b []byte
	b = append(b, "LogEntry{"...)
	if le != nil {
		b = strconv.AppendQuote(b, le.Operator.Name)
		b = append(b, ", "...)
		b = strconv.AppendQuote(b, le.Log.URL)
		b = append(b, ", "...)
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
	if le.LogEntry != nil {
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
