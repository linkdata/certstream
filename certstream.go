package certstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"golang.org/x/net/proxy"
)

//go:generate go run github.com/cparta/makeversion/v2/cmd/mkver@latest -name CertStream -out version.gen.go

type CertStream struct {
	OperatorFilter func(op *loglist3.Operator) bool // if nil, accepts all operators
	StatusFilter   func(loglist3.LogStatus) bool    // DefaultStatusFilter only accepts loglist3.LogStatusUsable
	MakeHttpClient func(cd proxy.ContextDialer) *http.Client
	BatchSize      int
	Workers        int
	proxy.ContextDialer
}

func DefaultStatusFilter(status loglist3.LogStatus) bool {
	return status == loglist3.UsableLogStatus
}

func DefaultMakeHttpClient(cd proxy.ContextDialer) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:           cd.DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// New returns a CertStream with reasonable defaults.
func New() *CertStream {
	return &CertStream{
		StatusFilter:   DefaultStatusFilter,
		MakeHttpClient: DefaultMakeHttpClient,
		BatchSize:      256,
		Workers:        2,
		ContextDialer:  &net.Dialer{},
	}
}

// Start returns a channel to read results from.
func (cs *CertStream) Start(ctx context.Context, logList *loglist3.LogList) (entryCh <-chan *LogEntry, err error) {
	sendEntryCh := make(chan *LogEntry, cs.Workers*cs.BatchSize)
	entryCh = sendEntryCh

	var logStreams []*LogStream
	for _, op := range logList.Operators {
		if cs.OperatorFilter == nil || cs.OperatorFilter(op) {
			for _, log := range op.Logs {
				if cs.StatusFilter == nil || cs.StatusFilter(log.State.LogStatus()) {
					if ls, err2 := NewLogStream(ctx, cs, op, log); err2 == nil {
						logStreams = append(logStreams, ls)
					} else {
						err = errors.Join(err, fmt.Errorf("%q %q: %v", op.Name, log.URL, err2))
					}
				}
			}
		}
	}

	go func() {
		var wg sync.WaitGroup
		defer close(sendEntryCh)
		for _, logStream := range logStreams {
			wg.Add(1)
			go func(ls *LogStream) {
				defer wg.Done()
				ls.Run(ctx, sendEntryCh)
			}(logStream)
		}
		wg.Wait()
	}()

	return
}
