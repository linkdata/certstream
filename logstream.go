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
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("%s:%s", ls.Operator.Name, ls.Log.URL)
}

func NewLogStream(ctx context.Context, cs *CertStream, op *loglist3.Operator, log *loglist3.Log) (ls *LogStream, err error) {
	var logClient *client.LogClient
	if logClient, err = client.New(log.URL, cs.MakeHttpClient(cs), jsonclient.Options{UserAgent: PkgName + "/" + PkgVersion}); err == nil {
		ls = &LogStream{
			CertStream: cs,
			Operator:   op,
			Log:        log,
			LogClient:  logClient,
		}
	}
	return
}

func (ls *LogStream) getSTH(ctx context.Context) (sth *ct.SignedTreeHead, err error) {
	backoff := 10
	for sth == nil {
		if sth, err = ls.LogClient.GetSTH(ctx); err == nil {
			return
		}
		if rspErr, ok := err.(client.RspError); ok {
			if rspErr.StatusCode == http.StatusTooManyRequests {
				time.Sleep(time.Second * time.Duration(backoff))
				backoff += 10
				continue
			}
		}
		return
	}
	return
}

func (ls *LogStream) Run(ctx context.Context, entryCh chan<- *LogEntry) {
	sth, err := ls.getSTH(ctx)
	if err == nil {
		if err = ls.VerifySTHSignature(*sth); err == nil {
			opts := &scanner.FetcherOptions{
				BatchSize:     ls.BatchSize,
				ParallelFetch: ls.Workers,
				StartIndex:    int64(sth.TreeSize),
				EndIndex:      int64(sth.TreeSize),
				Continuous:    true,
			}
			fetcher := scanner.NewFetcher(ls.LogClient, opts)
			fetcher.Run(ctx, func(eb scanner.EntryBatch) {
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
	if err != nil {
		klog.Errorf("%q %q: %v", ls.Operator.Name, ls.Log.URL, err)
	}
}
