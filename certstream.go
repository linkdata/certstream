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
	"github.com/jackc/pgx/v5"
)

type CertStream struct {
	Config                             // copy of config
	C          <-chan *LogEntry        // log entry channel
	HeadClient *http.Client            // main HTTP client, uses Config.HeadDialer
	TailClient *http.Client            // may be nil if not backfilling
	Operators  map[string]*LogOperator // operators by operator domain, valid after Start()
	DB         *PgDB
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
		cs.Config.Logger.Info("certstream: "+msg, args...)
	}
}

func (cs *CertStream) LogError(err error, msg string, args ...any) error {
	if err != nil && cs.Config.Logger != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			cs.Config.Logger.Error("certstream: "+msg, append(args, "err", err)...)
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

func (cs *CertStream) batcher(ctx context.Context, ch <-chan *LogEntry, wg *sync.WaitGroup) {
	defer wg.Done()
	if cdb := cs.DB; cdb != nil {
		batch := &pgx.Batch{}
		for {
			select {
			case <-ctx.Done():
				return
			case le := <-ch:
				batch.Queue(cdb.procNewEntry, cdb.queueEntry(le)...)
			default:
				if len(batch.QueuedQueries) > 0 {
					wg.Add(1)
					go func(batch *pgx.Batch) {
						defer wg.Done()
						cs.LogError(cdb.SendBatch(ctx, batch).Close(), "SendBatch")
					}(batch)
					batch = &pgx.Batch{}
				} else {
					time.Sleep(time.Millisecond * 100)
				}
			}
		}
	}
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

	if cs.DB, err = NewPgDB(ctx, cs); err == nil {
		var logList *loglist3.LogList
		if logList, err = GetLogList(ctx, cs.HeadClient, loglist3.AllLogListURL); err == nil {
			chanSize := BatchSize
			chanSize *= len(logList.Operators)
			sendEntryCh := make(chan *LogEntry, chanSize)
			batchCh := make(chan *LogEntry, chanSize)
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
							if cs.DB != nil {
								if err2 := cs.DB.Operator(ctx, logop); err2 != nil {
									err = errors.Join(err, fmt.Errorf("%q %q: %v", op.Name, log.URL, err2))
									logop = nil
								}
							}
							cs.Operators[opDom] = logop
						}
						if logop != nil {
							if ls, err2 := newLogStream(logop, cs.HeadClient, log, sendEntryCh, batchCh); err2 == nil {
								if cs.DB != nil {
									if err2 := cs.DB.Stream(ctx, ls); err2 != nil {
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
			cs.LogInfo("starting", "streams", operators)

			go func() {
				var wg sync.WaitGroup
				defer func() {
					close(sendEntryCh)
					close(batchCh)
					if cs.DB != nil {
						cs.DB.Close()
					}
				}()
				wg.Add(1)
				go cs.batcher(ctx, batchCh, &wg)
				for _, logOp := range cs.Operators {
					for _, logStream := range logOp.Streams {
						wg.Add(1)
						go logStream.run(ctx, &wg)
					}
				}
				wg.Wait()
			}()
		}
	}

	return
}
