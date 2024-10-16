package certstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/linkdata/certstream/certificate/v1"
	"golang.org/x/net/proxy"
)

type CertStream struct {
	OperatorFilter func(op *loglist3.Operator) bool // if nil, accepts all operators
	StatusFilter   func(loglist3.LogStatus) bool    // if nil, only accepts loglist3.LogStatusUsable
	BatchSize      int
	Workers        int
	proxy.ContextDialer
}

func defaultStatusFilter(status loglist3.LogStatus) bool {
	return status == loglist3.UsableLogStatus
}

// New returns a CertStream with reasonable defaults.
func New() *CertStream {
	return &CertStream{
		StatusFilter:  defaultStatusFilter,
		BatchSize:     256,
		Workers:       2,
		ContextDialer: &net.Dialer{},
	}
}

// Init returns the LogStreams that pass the filter functions and that initialize successfully.
func (cs *CertStream) Start(ctx context.Context, logList *loglist3.LogList) (certCh <-chan *certificate.Batch, err error) {
	batchCh := make(chan *certificate.Batch, cs.Workers)
	certCh = batchCh

	var logStreams []*LogStream
	for _, op := range logList.Operators {
		if cs.OperatorFilter == nil || cs.OperatorFilter(op) {
			for _, log := range op.Logs {
				if cs.StatusFilter == nil || cs.StatusFilter(log.State.LogStatus()) {
					var ls *LogStream
					if ls, err = NewLogStream(ctx, cs, op, log); err == nil {
						logStreams = append(logStreams, ls)
					} else {
						err = errors.Join(err, fmt.Errorf("%q %q: %v", op.Name, log.URL, err))
					}
				}
			}
		}
	}

	go func() {
		var wg sync.WaitGroup
		defer close(batchCh)
		for _, logStream := range logStreams {
			wg.Add(1)
			go func(ls *LogStream) {
				defer wg.Done()
				ls.Run(ctx, batchCh)
			}(logStream)
		}
		wg.Wait()
	}()

	return
}
