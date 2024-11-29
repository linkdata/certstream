package certpg

import (
	"context"
	"net/http"
	"sync/atomic"

	ct "github.com/google/certificate-transparency-go"
	"github.com/linkdata/certstream"
)

var BulkRange = int64(4096)

func (cdb *CertPG) backfillGaps(ctx context.Context, ls *certstream.LogStream, gapcounter *int64) {
	type gap struct {
		start int64
		end   int64
	}
	var gaps []gap
	if rows, err := cdb.stmtSelectGaps.QueryContext(ctx, ls.Id); cdb.LogError(err, "backfillGaps/Query", "url", ls.URL) == nil {
		for rows.Next() {
			var gap_start, gap_end int64
			if err = rows.Scan(&gap_start, &gap_end); cdb.LogError(err, "backfillGaps/Scan", "url", ls.URL) == nil {
				gaps = append(gaps, gap{start: gap_start, end: gap_end})
			}
			atomic.AddInt64(gapcounter, (gap_end-gap_start)+1)
		}
		rows.Close()
	}
	if lastindex := atomic.LoadInt64(&ls.LastIndex); lastindex != -1 {
		row := cdb.stmtSelectMaxIdx.QueryRowContext(ctx, ls.Id)
		var maxindex int64
		if err := row.Scan(&maxindex); cdb.LogError(err, "backfillGaps/MaxIndex", "url", ls.URL) == nil {
			if maxindex < lastindex {
				gaps = append(gaps, gap{start: maxindex + 1, end: lastindex})
			}
		}
	}
	for _, gap := range gaps {
		if l := cdb.Logger; l != nil {
			l.Info("certstream: gap", "url", ls.URL, "stream", ls.Id, "logindex", gap.start, "length", (gap.end-gap.start)+1)
		}
		ls.GetRawEntries(ctx, gap.start, gap.end, func(logindex int64, entry ct.LeafEntry) {
			atomic.AddInt64(gapcounter, -1)
			cdb.Entry(ctx, ls.MakeLogEntry(logindex, entry))
		})
	}
}

func (cdb *CertPG) BackfillStream(ctx context.Context, ls *certstream.LogStream) {
	httpClient := ls.HttpClient
	gapcounter := &ls.InsideGaps
	if cdb.ContextDialer != nil {
		if tp, ok := httpClient.Transport.(*http.Transport); ok {
			client := *httpClient
			tp = tp.Clone()
			tp.DialContext = cdb.ContextDialer.DialContext
			client.Transport = tp
			httpClient = &client
		}
	}
	if httpClient != ls.HttpClient {
		if ls2, err := certstream.NewLogStream(ls.LogOperator, httpClient, ls.Log); cdb.LogError(err, "BackfillStream", "url", ls.URL) == nil {
			ls2.Id = ls.Id
			ls2.Backfilled = atomic.LoadInt32(&ls.Backfilled)
			ls = ls2
		}
	}
	cdb.backfillGaps(ctx, ls, gapcounter)
	row := cdb.stmtSelectMinIdx.QueryRowContext(ctx, ls.Id)
	var minIndex int64
	if err := row.Scan(&minIndex); cdb.LogError(err, "Backfill/MinIndex", "url", ls.URL) == nil {
		if minIndex > 0 {
			if l := cdb.Logger; l != nil {
				l.Info("certstream: backlog", "url", ls.URL, "stream", ls.Id, "logindex", minIndex)
			}
			for minIndex > 0 {
				start := max(0, minIndex-BulkRange)
				stop := minIndex - 1
				ls.GetRawEntries(ctx, start, stop, func(logindex int64, entry ct.LeafEntry) {
					cdb.Entry(ctx, ls.MakeLogEntry(logindex, entry))
				})
				minIndex = start
			}
		}
	}
}
