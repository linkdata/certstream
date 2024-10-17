package certstream

import (
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
)

type LogEntry struct {
	Operator     *loglist3.Operator
	Log          *loglist3.Log
	Err          error           // error from RawLogEntryFromLeaf or ToLogEntry, or nil
	RawLogEntry  *ct.RawLogEntry // may be nil in case of error
	*ct.LogEntry                 // may be nil in case of error
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

func (le *LogEntry) DNSNames() (names []string) {
	if le.LogEntry != nil {
		if le.LogEntry.X509Cert != nil {
			names = le.LogEntry.X509Cert.DNSNames
		} else if le.LogEntry.Precert != nil {
			names = le.LogEntry.Precert.TBSCertificate.DNSNames
		}
	}
	return
}

func (le *LogEntry) Index() (index int64) {
	if le.RawLogEntry != nil {
		index = le.RawLogEntry.Index
	}
	return
}
