package certstream

import (
	"strconv"

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
