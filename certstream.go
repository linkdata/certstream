package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

//go:generate go run github.com/cparta/makeversion/v2/cmd/mkver@latest -name CertStream -out version.gen.go

type CertStream struct {
	MakeHttpClient func(op *loglist3.Operator, log *loglist3.Log) *http.Client // return nil to skip the operator or log
	BatchSize      int
	ParallelFetch  int
}

var DefaultHttpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// DefaultMakeHttpClient returns DefaultHttpClient for all operators and logs where the log is usable.
func DefaultMakeHttpClient(op *loglist3.Operator, log *loglist3.Log) (httpClient *http.Client) {
	if log.State.LogStatus() == loglist3.UsableLogStatus {
		httpClient = DefaultHttpClient
	}
	return
}

// New returns a CertStream with reasonable defaults.
func New() *CertStream {
	return &CertStream{
		MakeHttpClient: DefaultMakeHttpClient,
		BatchSize:      256,
		ParallelFetch:  2,
	}
}

// Start returns a channel to read results from.
func (cs *CertStream) Start(ctx context.Context, logList *loglist3.LogList) (entryCh <-chan *LogEntry, err error) {
	sendEntryCh := make(chan *LogEntry, cs.ParallelFetch*cs.BatchSize)
	entryCh = sendEntryCh

	var logStreams []*LogStream
	for _, op := range logList.Operators {
		for _, log := range op.Logs {
			if httpClient := cs.MakeHttpClient(op, log); httpClient != nil {
				if ls, err2 := NewLogStream(cs, httpClient, op, log); err2 == nil {
					logStreams = append(logStreams, ls)
				} else {
					err = errors.Join(err, fmt.Errorf("%q %q: %v", op.Name, log.URL, err2))
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
