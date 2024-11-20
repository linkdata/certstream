package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/linkdata/bwlimit"
)

type LogStreamInitFn func(op *loglist3.Operator, log *loglist3.Log) (httpClient *http.Client)

type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

type CertStream struct {
	LogStreamInit    LogStreamInitFn
	Operators        map[string]*LogOperator // operators by operator domain
	*bwlimit.Limiter                         // bandwidth limiter used for following CT log heads
	Logger
}

var DefaultHttpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxConnsPerHost:       2,
		MaxIdleConnsPerHost:   2,
		DisableKeepAlives:     false,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	},
}

// DefaultLogStreamInit returns DefaultHttpClient for all operators and logs where the log is usable.
func DefaultLogStreamInit(op *loglist3.Operator, log *loglist3.Log) (httpClient *http.Client) {
	if log.State.LogStatus() == loglist3.UsableLogStatus {
		httpClient = DefaultHttpClient
	}
	return
}

// New returns a CertStream with reasonable defaults.
func New() *CertStream {
	return &CertStream{
		LogStreamInit: DefaultLogStreamInit,
		Operators:     make(map[string]*LogOperator),
	}
}

func (cs *CertStream) LogError(err error, msg string, args ...any) {
	if err != nil && cs.Logger != nil {
		if !errors.Is(err, context.Canceled) {
			cs.Logger.Error(msg, append(args, "err", err)...)
		}
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
	if logList == nil {
		logList, err = GetLogList(ctx, DefaultHttpClient, loglist3.AllLogListURL)
	}

	chanSize := BatchSize
	if logList != nil {
		chanSize *= len(logList.Operators)
	}
	sendEntryCh := make(chan *LogEntry, chanSize)
	entryCh = sendEntryCh

	if logList != nil {
		httpClients := map[*http.Client]bwlimit.DialContextFn{}
		for _, op := range logList.Operators {
			for _, log := range op.Logs {
				if httpClient := cs.LogStreamInit(op, log); httpClient != nil {
					opDom := OperatorDomain(log.URL)
					logop := cs.Operators[opDom]
					if logop == nil {
						logop = &LogOperator{
							CertStream: cs,
							Operator:   op,
							Domain:     opDom,
						}
						sort.Strings(op.Email)
					}
					if cs.Limiter != nil {
						if dc, ok := httpClients[httpClient]; !ok {
							if tp, ok := httpClient.Transport.(*http.Transport); ok {
								dc = tp.DialContext
								httpClients[httpClient] = dc
								tp.DialContext = cs.Limiter.Wrap(dc)
							}
						}
					}
					if ls, err2 := NewLogStream(logop, httpClient, log); err2 == nil {
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
