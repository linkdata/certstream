package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

type CertStream struct {
	Config                             // copy of config
	C          <-chan *LogEntry        // log entry channel
	HeadClient *http.Client            // main HTTP client, uses Config.HeadDialer
	TailClient *http.Client            // may be nil if not backfilling
	Operators  map[string]*LogOperator // operators by operator domain, valid after Start()
	cdb        *PgDB
}

var DefaultTransport = &http.Transport{
	TLSHandshakeTimeout:   30 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	MaxConnsPerHost:       2,
	MaxIdleConnsPerHost:   2,
	DisableKeepAlives:     false,
	ExpectContinueTimeout: 1 * time.Second,
	ForceAttemptHTTP2:     true,
}

func (cs *CertStream) LogInfo(msg string, args ...any) {
	if cs.Config.Logger != nil {
		cs.Config.Logger.Info(msg, args...)
	}
}

func (cs *CertStream) LogError(err error, msg string, args ...any) error {
	if err != nil && cs.Config.Logger != nil {
		if !errors.Is(err, context.Canceled) {
			cs.Config.Logger.Error(msg, append(args, "err", err)...)
		}
	}
	return err
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

func Start(ctx context.Context, cfg *Config) (cs *CertStream, err error) {
	tp := DefaultTransport.Clone()
	tp.DialContext = cfg.HeadDialer.DialContext
	cs = &CertStream{
		Config: *cfg,
		HeadClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tp,
		},
		Operators: map[string]*LogOperator{},
	}

	if cs.Config.TailDialer != nil {
		tp = DefaultTransport.Clone()
		tp.DialContext = cfg.TailDialer.DialContext
		cs.TailClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: tp,
		}
	}

	if cs.cdb, err = NewPgDB(ctx, cs); err == nil {
		var logList *loglist3.LogList
		if logList, err = GetLogList(ctx, cs.HeadClient, loglist3.AllLogListURL); err == nil {
			chanSize := BatchSize
			chanSize *= len(logList.Operators)
			sendEntryCh := make(chan *LogEntry, chanSize)
			cs.C = sendEntryCh

			for _, op := range logList.Operators {
				for _, log := range op.Logs {
					if log.State.LogStatus() == loglist3.UsableLogStatus {
						opDom := OperatorDomain(log.URL)
						logop := cs.Operators[opDom]
						if logop == nil {
							logop = &LogOperator{
								CertStream: cs,
								Operator:   op,
								Domain:     opDom,
							}
							sort.Strings(op.Email)
							if cs.cdb != nil {
								if err2 := cs.cdb.Operator(ctx, logop); err2 != nil {
									err = errors.Join(err, fmt.Errorf("%q %q: %v", op.Name, log.URL, err2))
									logop = nil
								}
							}
							cs.Operators[opDom] = logop
						}
						if logop != nil {
							if ls, err2 := NewLogStream(logop, cs.HeadClient, log); err2 == nil {
								if cs.cdb != nil {
									if err2 := cs.cdb.Stream(ctx, ls); err2 != nil {
										err = errors.Join(err, fmt.Errorf("%q %q: %v", op.Name, log.URL, err2))
										ls = nil
									}
								}
								if ls != nil {
									logop.Streams = append(logop.Streams, ls)
								}
							}
						}
					}
				}
			}

			var operators []string
			for opdom, lo := range cs.Operators {
				operators = append(operators, fmt.Sprintf("%s*%d", opdom, len(lo.Streams)))
			}
			slices.Sort(operators)
			cs.LogInfo("certstream", "streams", operators)

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
		}
	}

	return
}
