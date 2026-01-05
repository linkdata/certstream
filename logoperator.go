package certstream

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
)

type LogOperator struct {
	*CertStream
	*loglist3.Operator
	Domain   string       // e.g. "letsencrypt.org" or "googleapis.com"
	Count    atomic.Int64 // atomic; sum of the stream's Count
	Id       int32        // database ID, if available
	mu       sync.Mutex   // protects following
	streams  map[string]*LogStream
	errcount int
	errors   []*StreamError
}

func (lo *LogOperator) StreamCount() (n int) {
	lo.mu.Lock()
	n = len(lo.streams)
	lo.mu.Unlock()
	return
}

func (lo *LogOperator) ErrorCount() (n int) {
	lo.mu.Lock()
	n = lo.errcount
	lo.mu.Unlock()
	return
}

func (lo *LogOperator) Errors() (errs []*StreamError) {
	lo.mu.Lock()
	errs = append(errs, lo.errors...)
	lo.mu.Unlock()
	return
}

func (lo *LogOperator) addError(ls *LogStream, err error) {
	if err != nil {
		now := time.Now()
		lo.mu.Lock()
		defer lo.mu.Unlock()
		lo.errors = append(lo.errors, &StreamError{LogStream: ls, When: now, Err: err})
		if len(lo.errors) > MaxErrors {
			lo.errors = slices.Delete(lo.errors, 0, len(lo.errors)-MaxErrors)
		}
		ls.errcount++
	}
}

func (lo *LogOperator) Streams() (sl []*LogStream) {
	lo.mu.Lock()
	for _, s := range lo.streams {
		sl = append(sl, s)
	}
	lo.mu.Unlock()
	slices.SortFunc(sl, func(a, b *LogStream) int { return strings.Compare(a.URL(), b.URL()) })
	return
}

func (lo *LogOperator) GetStreamByID(id int32) (ls *LogStream) {
	lo.mu.Lock()
	for _, ls = range lo.streams {
		if ls.Id == id {
			break
		}
	}
	lo.mu.Unlock()
	return
}

func (lo *LogOperator) makeStream(log *loglist3.Log) (ls *LogStream, err error) {
	var headLogClient *client.LogClient
	if headLogClient, err = client.New(log.URL, lo.HeadClient, jsonclient.Options{}); err == nil {
		var tailLogClient *client.LogClient
		if lo.TailClient != nil {
			tailLogClient, err = client.New(log.URL, lo.TailClient, jsonclient.Options{})
		}
		ls = &LogStream{
			LogOperator: lo,
			Log:         log,
			HeadClient:  headLogClient,
			TailClient:  tailLogClient,
		}
		ls.MinIndex.Store(-1)
		ls.MaxIndex.Store(-1)
		ls.LastIndex.Store(-1)
	}
	return
}

func (lo *LogOperator) ensureStream(ctx context.Context, log *loglist3.Log, wg *sync.WaitGroup) (err error) {
	lo.mu.Lock()
	ls := lo.streams[log.URL]
	lo.mu.Unlock()
	if ls == nil {
		if ls, err = lo.makeStream(log); err == nil {
			if db := lo.DB(); db != nil {
				if err = db.ensureStream(ctx, ls); err == nil {
					lo.mu.Lock()
					lo.streams[log.URL] = ls
					lo.mu.Unlock()
					wg.Add(1)
					go ls.run(ctx, wg)
				}
			}
		}
	}
	return
}
