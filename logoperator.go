package certstream

import "github.com/google/certificate-transparency-go/loglist3"

type LogOperator struct {
	*CertStream
	*loglist3.Operator
	Domain  string // e.g. "letsencrypt.org" or "googleapis.com"
	Streams []*LogStream
}
