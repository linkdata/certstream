package certstream

import (
	"context"
	"fmt"
	"net/http"
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
	startIndex int64
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("LogStream{%q, %q}", ls.Operator.Name, ls.Log.URL)
}

func NewLogStream(cs *CertStream, httpClient *http.Client, startIndex int64, op *loglist3.Operator, log *loglist3.Log) (ls *LogStream, err error) {
	var logClient *client.LogClient
	if logClient, err = client.New(log.URL, httpClient, jsonclient.Options{UserAgent: PkgName + "/" + PkgVersion}); err == nil {
		ls = &LogStream{
			CertStream: cs,
			Operator:   op,
			Log:        log,
			LogClient:  logClient,
			startIndex: startIndex,
		}
	}
	return
}

func (ls *LogStream) getSTH(ctx context.Context) (sth *ct.SignedTreeHead, err error) {
	backoff := time.Second * 2
	for sth == nil && err == nil {
		if sth, err = ls.LogClient.GetSTH(ctx); err != nil {
			if rspErr, ok := err.(client.RspError); ok {
				if rspErr.StatusCode == http.StatusTooManyRequests {
					time.Sleep(backoff)
					backoff = min(backoff*2, time.Minute)
					err = nil
				}
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
	sth, err := ls.getSTH(ctx)
	if err == nil {
		if err = ls.VerifySTHSignature(*sth); err == nil {
			endIndex := int64(sth.TreeSize) //#nosec G115
			startIndex := min(ls.startIndex, endIndex)
			if startIndex < 0 {
				startIndex = endIndex
			}
			opts := &scanner.FetcherOptions{
				BatchSize:     ls.BatchSize,
				ParallelFetch: ls.ParallelFetch,
				StartIndex:    startIndex,
				EndIndex:      endIndex,
				Continuous:    true,
			}
			fetcher := scanner.NewFetcher(ls.LogClient, opts)
			err = fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				for n, entry := range eb.Entries {
					var le *ct.LogEntry
					index := eb.Start + int64(n)
					rle, err := ct.RawLogEntryFromLeaf(index, &entry)
					if err == nil {
						le, err = rle.ToLogEntry()
					}
					entryCh <- &LogEntry{
						Operator:    ls.Operator,
						Log:         ls.Log,
						Err:         err,
						RawLogEntry: rle,
						LogEntry:    le,
					}
				}
			})
		}
	}
	ls.maybeLog(err)
}
