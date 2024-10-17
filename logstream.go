package certstream

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
	"k8s.io/klog/v2"
)

type LogStream struct {
	*CertStream
	*loglist3.Operator
	*loglist3.Log
	*client.LogClient
	OperatorDomain string // e.g. "letsencrypt.org" or "googleapis.com"
	startIndex     int64
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q}", ls.Log.URL)
}

func makeOperatorDomain(host string) string {
	if idx := strings.LastIndexByte(host, ':'); idx > 0 {
		host = host[:idx]
	}
	if idx := strings.LastIndexByte(host, '.'); idx > 0 {
		if idx := strings.LastIndexByte(host[:idx], '.'); idx > 0 {
			host = host[idx+1:]
		}
	}
	return host
}

func NewLogStream(cs *CertStream, httpClient *http.Client, startIndex int64, op *loglist3.Operator, log *loglist3.Log) (ls *LogStream, err error) {
	var u *url.URL
	if u, err = url.Parse(log.URL); err == nil {
		var logClient *client.LogClient
		if logClient, err = client.New(log.URL, httpClient, jsonclient.Options{UserAgent: PkgName + "/" + PkgVersion}); err == nil {
			if startIndex < 0 {
				startIndex = math.MaxInt64
			}
			ls = &LogStream{
				CertStream:     cs,
				Operator:       op,
				Log:            log,
				LogClient:      logClient,
				OperatorDomain: makeOperatorDomain(u.Host),
				startIndex:     startIndex,
			}
		}
	}
	return
}

func (ls *LogStream) maybeLog(err error) {
	if err != nil {
		klog.Errorf("%s: %v", ls, err)
	}
}

func (ls *LogStream) Run(ctx context.Context, entryCh chan<- *LogEntry) {
	opts := &scanner.FetcherOptions{
		BatchSize:     ls.BatchSize,
		ParallelFetch: ls.ParallelFetch,
		Continuous:    true,
	}
	fetcher := scanner.NewFetcher(ls.LogClient, opts)

	var sth *ct.SignedTreeHead
	var err error
	backoff := time.Second * 2
	for sth == nil && err == nil {
		if sth, err = fetcher.Prepare(ctx); err != nil {
			if rspErr, ok := err.(client.RspError); ok {
				if rspErr.StatusCode == http.StatusTooManyRequests {
					klog.Infof("retry prepare %q", ls.URL)
					time.Sleep(backoff)
					backoff = min(backoff*2, time.Minute)
					err = nil
				}
			}
		}
	}

	if err == nil {
		if err = ls.VerifySTHSignature(*sth); err == nil {
			opts.StartIndex = min(ls.startIndex, opts.EndIndex)
			klog.Infof("fetching %q from %v", ls.URL, opts.StartIndex)
			err = fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				for n, entry := range eb.Entries {
					var le *ct.LogEntry
					index := eb.Start + int64(n)
					rle, leaferr := ct.RawLogEntryFromLeaf(index, &entry)
					if leaferr == nil {
						le, leaferr = rle.ToLogEntry()
					}
					entryCh <- &LogEntry{
						LogStream:   ls,
						Err:         leaferr,
						RawLogEntry: rle,
						LogEntry:    le,
					}
				}
			})
		}
	}
	ls.maybeLog(err)
}
