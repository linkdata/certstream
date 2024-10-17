package certstream

import (
	"context"
	"fmt"
	"math"
	"net/http"

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
		if startIndex < 0 {
			startIndex = math.MaxInt64
		}
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
	sth, err := fetcher.Prepare(ctx)
	if err == nil {
		if err = ls.VerifySTHSignature(*sth); err == nil {
			opts.StartIndex = min(ls.startIndex, opts.EndIndex)
			err = fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				for n, entry := range eb.Entries {
					var le *ct.LogEntry
					index := eb.Start + int64(n)
					rle, leaferr := ct.RawLogEntryFromLeaf(index, &entry)
					if leaferr == nil {
						le, leaferr = rle.ToLogEntry()
					}
					entryCh <- &LogEntry{
						Operator:    ls.Operator,
						Log:         ls.Log,
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
