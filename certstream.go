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

type LogStreamInitFn func(op *loglist3.Operator, log *loglist3.Log) (httpClient *http.Client, startIndex int64)

type CertStream struct {
	LogStreamInit LogStreamInitFn
	BatchSize     int
	ParallelFetch int
	Operators     map[string]*LogOperator // operators by operator domain
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
		Operators:     make(map[string]*LogOperator),
	}
}

func (cs *CertStream) CountStreams() (running, stopped int) {
	for _, logop := range cs.Operators {
		for _, strm := range logop.Streams {
			if strm.Stopped() {
				stopped++
			} else {
				running++
			}
		}
	}
	return
}

// Start returns a channel to read results from. If logList is nil, we fetch the list from loglist3.AllLogListURL using DefaultHttpClient.
func (cs *CertStream) Start(ctx context.Context, logList *loglist3.LogList) (entryCh <-chan *LogEntry, err error) {
	sendEntryCh := make(chan *LogEntry, cs.ParallelFetch*cs.BatchSize)
	entryCh = sendEntryCh

	if logList == nil {
		logList, err = GetLogList(ctx, DefaultHttpClient, loglist3.AllLogListURL)
	}

	if logList != nil {
		for _, op := range logList.Operators {
			for _, log := range op.Logs {
				if httpClient, startIndex := cs.LogStreamInit(op, log); httpClient != nil {
					opDom := OperatorDomain(log.URL)
					logop := cs.Operators[opDom]
					if logop == nil {
						logop = &LogOperator{
							CertStream: cs,
							Operator:   op,
							Domain:     opDom,
						}
					}
					if ls, err2 := NewLogStream(logop, httpClient, startIndex, log); err2 == nil {
						cs.Operators[opDom] = logop
						logop.Streams = append(logop.Streams, ls)
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
		for _, logOp := range cs.Operators {
			for _, logStream := range logOp.Streams {
				wg.Add(1)
				go func(ls *LogStream) {
					defer wg.Done()
					ls.Run(ctx, sendEntryCh)
				}(logStream)
			}
		}
		wg.Wait()
	}()

	return
}
