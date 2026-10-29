package certstream

import (
	"context"
	"maps"
	"net/http"
	"path"
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
	Domain      string             // e.g. "letsencrypt.org" or "googleapis.com"
	Count       atomic.Int64       // atomic; sum of the stream's Count
	Status429   atomic.Int64       // atomic; number of 429 Too Many Requests
	Id          int32              // database ID, if available
	operator    *loglist3.Operator // read-only
	mu          sync.Mutex         // protects following
	statuses    map[int]int        // HTTP status code counter
	streams     map[string]*LogStream
	errcount    int
	errors      []*StreamError
	limitMu     sync.Mutex // protects limit, notifications, and reader active counts
	limit       int
	limitWait   chan struct{}
	limitChange chan struct{}
}

func (lo *LogOperator) Name() string {
	return lo.operator.Name
}

func (lo *LogOperator) Email() []string {
	return lo.operator.Email
}

func (lo *LogOperator) initialConcurrency() int {
	if n := lo.ProviderConcurrency[lo.Domain]; n > 0 {
		return n
	}
	return max(1, lo.Concurrency)
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

func (lo *LogOperator) addStatus(statuscode int) {
	if statuscode > http.StatusOK {
		if statuscode == http.StatusTooManyRequests {
			lo.Status429.Add(1)
		}
		lo.mu.Lock()
		if lo.statuses == nil {
			lo.statuses = make(map[int]int)
		}
		lo.statuses[statuscode]++
		lo.mu.Unlock()
	}
}

func (lo *LogOperator) StatusCounts() (m map[int]int) {
	lo.mu.Lock()
	m = maps.Clone(lo.statuses)
	lo.mu.Unlock()
	return
}

func (lo *LogOperator) CallCount() (n int64) {
	lo.mu.Lock()
	for _, s := range lo.streams {
		n += s.backoff.Count()
	}
	lo.mu.Unlock()
	return
}

func (lo *LogOperator) Errors() (errs []*StreamError) {
	lo.mu.Lock()
	errs = append(errs, lo.errors...)
	lo.mu.Unlock()
	return
}

func (lo *LogOperator) addError(ls *LogStream, err error) (errcount int) {
	if err != nil {
		now := time.Now()
		lo.mu.Lock()
		defer lo.mu.Unlock()
		lo.errors = append(lo.errors, &StreamError{LogStream: ls, When: now, Err: err})
		if len(lo.errors) > MaxErrors {
			lo.errors = slices.Delete(lo.errors, 0, len(lo.errors)-MaxErrors)
		}
		ls.errcount++
		errcount = ls.errcount
	}
	return
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
	tmpls := &LogStream{
		LogOperator: lo,
		log:         log,
		backoff:     newLogStreamBackoff(time.Second, 30*time.Second, 2, true),
	}

	if lo.DataDir != "" {
		logfile := path.Join(lo.DataDir, urlToFileString(log.URL)+".log")
		tmpls.Logger = newToggledLogger(logfile, &tmpls.LogToggle)
	}

	if tmpls.headClient, err = client.New(log.URL, newLimitedProviderClient(lo.HeadClient, lo, nil), jsonclient.Options{}); err == nil {
		if lo.TailClient != nil {
			tmpls.tailClient, err = client.New(log.URL, newLimitedProviderClient(lo.TailClient, lo, nil), jsonclient.Options{})
		}
		ls = tmpls
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
			if err = lo.DB().ensureStream(ctx, ls); err == nil {
				streamCtx, cancel := context.WithCancel(ctx)
				ls.cancel = cancel
				ls.done = make(chan struct{})
				lo.mu.Lock()
				lo.streams[log.URL] = ls
				lo.mu.Unlock()
				wg.Add(1)
				go ls.run(streamCtx, wg)
			}
		}
	}
	return
}

func urlToFileString(urlstr string) (s string) {
	return strings.Trim(strings.ReplaceAll(strings.TrimPrefix(urlstr, "https://"), "/", "_"), "_")
}

func (lo *LogOperator) makeTiledStream(log *loglist3.TiledLog) (ls *LogStream, err error) {
	tmpls := &LogStream{
		LogOperator: lo,
		tiledLog:    log,
		backoff:     newLogStreamBackoff(time.Second, 30*time.Second, 2, true),
	}

	if lo.DataDir != "" {
		logfile := path.Join(lo.DataDir, urlToFileString(log.MonitoringURL)+".log")
		tmpls.Logger = newToggledLogger(logfile, &tmpls.LogToggle)
	}

	cacheDir := getCacheDir(lo.DataDir, log.MonitoringURL)
	// The HTTP transports enforce live limits; torchwood's fixed cap stays unset.
	if tmpls.headTile, err = newSunlightClient(log, newLimitedProviderClient(lo.HeadClient, lo, nil), tmpls.Logger, cacheDir); err == nil {
		if lo.TailClient != nil {
			tailClient := newLimitedProviderClient(lo.TailClient, lo, nil)
			tmpls.tailTile, err = newSunlightClient(log, tailClient, tmpls.Logger, cacheDir)
			if err == nil && lo.TailDialer != nil {
				gapClient := newLimitedProviderClient(lo.TailClient, lo, tailClient.Transport.(*retryAfterTransport))
				tmpls.gapTile, err = newSunlightClient(log, gapClient, tmpls.Logger, "")
			}
		}
		if err == nil {
			ls = tmpls
			ls.MinIndex.Store(-1)
			ls.MaxIndex.Store(-1)
			ls.LastIndex.Store(-1)
		}
	}
	return
}

func (lo *LogOperator) ensureTiledStream(ctx context.Context, log *loglist3.TiledLog, wg *sync.WaitGroup) (err error) {
	lo.mu.Lock()
	ls := lo.streams[log.MonitoringURL]
	lo.mu.Unlock()
	if ls == nil {
		if ls, err = lo.makeTiledStream(log); err == nil {
			if err = lo.DB().ensureStream(ctx, ls); err == nil {
				streamCtx, cancel := context.WithCancel(ctx)
				ls.cancel = cancel
				ls.done = make(chan struct{})
				lo.mu.Lock()
				lo.streams[log.MonitoringURL] = ls
				lo.mu.Unlock()
				wg.Add(1)
				go ls.run(streamCtx, wg)
			}
		}
	}
	return
}
