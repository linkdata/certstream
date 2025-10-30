package certstream

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/linkdata/bwlimit"
)

type CertStream struct {
	Config                       // copy of config
	C           <-chan *LogEntry // log entry channel
	HeadClient  *http.Client     // main HTTP client, uses Config.HeadDialer
	TailClient  *http.Client     // may be nil if not backfilling
	tailLimiter *bwlimit.Limiter // master tail limiter, if known
	subLimiter  *bwlimit.Limiter // sub tail limiter
	mu          sync.Mutex       // protects following
	db          *PgDB
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

func (cs *CertStream) DB() (db *PgDB) {
	cs.mu.Lock()
	db = cs.db
	cs.mu.Unlock()
	return
}

func (cs *CertStream) Close() {
	cs.mu.Lock()
	seCh := cs.sendEntryCh
	cs.sendEntryCh = nil
	db := cs.db
	cs.db = nil
	cs.mu.Unlock()
	if seCh != nil {
		// drain
		ok := true
		for ok {
			select {
			case _, ok = <-seCh:
			default:
				ok = false
			}
		}
		close(seCh)
	}
	if db != nil {
		db.Close()
	}
}

func (cs *CertStream) run(ctx context.Context, wg *sync.WaitGroup) {
	ticker := time.NewTicker(time.Hour * 24)

	defer func() {
		ticker.Stop()
		wg.Done()
		cs.Close()
	}()

	_ = cs.LogError(cs.updateStreams(ctx, wg), "CertStream:run@1")

	if db := cs.DB(); db != nil {
		wg.Add(2)
		go db.runWorkers(ctx, wg)
		go db.estimator(ctx, wg)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = cs.LogError(cs.updateStreams(ctx, wg), "CertStream:run@2")
		}
	}
}

func Start(ctx context.Context, wg *sync.WaitGroup, cfg *Config) (cs *CertStream, err error) {
	tailDialer := cfg.TailDialer
	if tailDialer == nil {
		tailDialer = cfg.HeadDialer
	}
	subLimiter := bwlimit.NewLimiter()
	var tailLimiter *bwlimit.Limiter
	if bwdialer, ok := tailDialer.(*bwlimit.Dialer); ok {
		tailLimiter = bwdialer.Limiter
		subLimiter.Reads.Limit.Store(tailLimiter.Reads.Limit.Load())
	}
	tailDialer = subLimiter.Wrap(tailDialer)

	tphead := DefaultTransport.Clone()
	tphead.DialContext = cfg.HeadDialer.DialContext
	tptail := DefaultTransport.Clone()
	tptail.DialContext = tailDialer.DialContext

	cs = &CertStream{
		Config: *cfg,
		HeadClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tphead,
		},
		TailClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tptail,
		},
		tailLimiter: tailLimiter,
		subLimiter:  subLimiter,
		operators:   map[string]*LogOperator{},
	}

	var db *PgDB
	if db, err = NewPgDB(ctx, cs); err == nil {
		cs.mu.Lock()
		cs.db = db
		cs.sendEntryCh = make(chan *LogEntry, 1024*8)
		cs.C = cs.sendEntryCh
		cs.mu.Unlock()
		wg.Add(1)
		go cs.run(ctx, wg)
	}

	return
}
