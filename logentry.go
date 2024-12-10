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

// Cert returns the cert from LogEntry.X509Cert or LogEntry.Precert.TBSCertificate, or nil.
func (le *LogEntry) Cert() (cert *x509.Certificate) {
	if le.LogEntry != nil {
		if cert = le.LogEntry.X509Cert; cert == nil {
			if le.LogEntry.Precert != nil {
				cert = le.LogEntry.Precert.TBSCertificate
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

func (le *LogEntry) IsPreCert() (yes bool) {
	if le.LogEntry != nil {
		yes = le.LogEntry.Precert != nil
	}
	return
}

func (le *LogEntry) Seen() (seen time.Time) {
	if le.RawLogEntry != nil {
		tse := int64(le.RawLogEntry.Leaf.TimestampedEntry.Timestamp) //#nosec G115
		seen = time.UnixMilli(tse).UTC()
	} else {
		seen = time.Now().UTC()
	}
	return
}

func (le *LogEntry) Signature() (sig []byte) {
	if le.RawLogEntry != nil {
		shasig := sha256.Sum256(le.RawLogEntry.Cert.Data)
		sig = shasig[:]
	} else if cert := le.Cert(); cert != nil {
		shasig := sha256.Sum256(cert.RawTBSCertificate)
		sig = shasig[:]
	}
	return
}
