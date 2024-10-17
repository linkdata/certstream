package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

//go:generate go run github.com/cparta/makeversion/v2/cmd/mkver@latest -name CertStream -out version.gen.go

type LogStreamInitFn func(op *loglist3.Operator, log *loglist3.Log) (httpClient *http.Client, startIndex int64)

type CertStream struct {
	LogStreamInit LogStreamInitFn
	BatchSize     int
	ParallelFetch int
	Operators     []string // list active OperatorDomain
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

// DefaultLogStreamInit returns (DefaultHttpClient, -1) for all operators and logs where the log is usable.
func DefaultLogStreamInit(op *loglist3.Operator, log *loglist3.Log) (httpClient *http.Client, startIndex int64) {
	if log.State.LogStatus() == loglist3.UsableLogStatus {
		httpClient = DefaultHttpClient
		startIndex = -1
	}
	return
}

// New returns a CertStream with reasonable defaults.
func New() *CertStream {
	return &CertStream{
		LogStreamInit: DefaultLogStreamInit,
		BatchSize:     256,
		ParallelFetch: 2,
	}
}

// Start returns a channel to read results from. If logList is nil, we fetch the list from loglist3.AllLogListURL using DefaultHttpClient.
func (cs *CertStream) Start(ctx context.Context, logList *loglist3.LogList) (entryCh <-chan *LogEntry, err error) {
	var logStreams []*LogStream
	sendEntryCh := make(chan *LogEntry, cs.ParallelFetch*cs.BatchSize)
	entryCh = sendEntryCh

	if logList == nil {
		logList, err = GetLogList(ctx, DefaultHttpClient, loglist3.AllLogListURL)
	}

	if logList != nil {
		for _, op := range logList.Operators {
			for _, log := range op.Logs {
				if httpClient, startIndex := cs.LogStreamInit(op, log); httpClient != nil {
					if ls, err2 := NewLogStream(cs, httpClient, startIndex, op, log); err2 == nil {
						if !slices.Contains(cs.Operators, ls.OperatorDomain) {
							cs.Operators = append(cs.Operators, ls.OperatorDomain)
						}
						logStreams = append(logStreams, ls)
					} else {
						err = errors.Join(err, fmt.Errorf("%q %q: %v", op.Name, log.URL, err2))
					}
				}
			}
		}
		slices.Sort(cs.Operators)
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
