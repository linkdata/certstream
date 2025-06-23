package certstream

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

type CertStream struct {
	Config                       // copy of config
	C           <-chan *LogEntry // log entry channel
	HeadClient  *http.Client     // main HTTP client, uses Config.HeadDialer
	TailClient  *http.Client     // may be nil if not backfilling
	DB          *PgDB
	mu          sync.Mutex // protects following
	sendEntryCh chan *LogEntry
	operators   map[string]*LogOperator // operators by operator domain, valid after Start()
}

var DefaultTransport = &http.Transport{
	TLSHandshakeTimeout:   30 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
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
			if unwrapper, ok := err.(interface{ Unwrap() []error }); ok {
				for _, e := range unwrapper.Unwrap() {
					cs.Config.Logger.Error("certstream: "+msg, append(args, "err", e)...)
				}
			} else {
				cs.Config.Logger.Error("certstream: "+msg, append(args, "err", err)...)
			}
		}
	}
	return err
}

func (cs *CertStream) Operators() (operators []*LogOperator) {
	cs.mu.Lock()
	for _, logop := range cs.operators {
		operators = append(operators, logop)
	}
	cs.mu.Unlock()
	slices.SortFunc(operators, func(a, b *LogOperator) int { return strings.Compare(a.Name, b.Name) })
	return
}

func (cs *CertStream) CountStreams() (n int) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, logop := range cs.operators {
		logop.mu.Lock()
		n += len(logop.streams)
		logop.mu.Unlock()
	}
	return
}

func (cs *CertStream) getSendEntryCh() (ch chan *LogEntry) {
	cs.mu.Lock()
	ch = cs.sendEntryCh
	cs.mu.Unlock()
	return
}

func (cs *CertStream) Close() {
	cs.mu.Lock()
	close(cs.sendEntryCh)
	cs.sendEntryCh = nil
	cs.mu.Unlock()
	if cs.DB != nil {
		cs.DB.Close()
	}
}

func (cs *CertStream) run(ctx context.Context, wg *sync.WaitGroup) {
	ticker := time.NewTicker(time.Hour * 24)

	defer func() {
		ticker.Stop()
		wg.Done()
	}()

	cs.LogError(cs.updateStreams(ctx, wg), "CertStream:run@1")

	if cs.DB != nil {
		wg.Add(2)
		// go cs.DB.ensureDnsnameIndex(ctx, wg)
		go cs.DB.runWorkers(ctx, wg)
		go cs.DB.estimator(ctx, wg)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cs.LogError(cs.updateStreams(ctx, wg), "CertStream:run@2")
		}
	}
}

func Start(ctx context.Context, wg *sync.WaitGroup, cfg *Config) (cs *CertStream, err error) {
	tp := DefaultTransport.Clone()
	tp.DialContext = cfg.HeadDialer.DialContext
	cs = &CertStream{
		Config: *cfg,
		HeadClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tp,
		},
		operators: map[string]*LogOperator{},
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
		cs.mu.Lock()
		cs.sendEntryCh = make(chan *LogEntry, 1024*8)
		cs.C = cs.sendEntryCh
		cs.mu.Unlock()
		wg.Add(1)
		go cs.run(ctx, wg)
	}

	return
}
