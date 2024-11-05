package certpg

import (
	"context"

	ct "github.com/google/certificate-transparency-go"
	"github.com/linkdata/certstream"
)

var BulkRange = int64(4096)

func (cdb *CertPG) backfillGaps(ctx context.Context, ls *certstream.LogStream) {
	if rows, err := cdb.QueryContext(ctx, setPrefix(SelectGaps), ls.Id); cdb.LogError(err, "backfillGaps/Query", "url", ls.URL) == nil {
		defer rows.Close()
		for rows.Next() {
			var gap_start, gap_end int64
			if err = rows.Scan(&gap_start, &gap_end); cdb.LogError(err, "backfillGaps/Scan", "url", ls.URL) == nil {
				ls.GetRawEntries(ctx, gap_start, gap_end, func(logindex int64, entry ct.LeafEntry) {
					cdb.Entry(ctx, ls.MakeLogEntry(logindex, entry))
				})
			}
		}
	}
}

func (cdb *CertPG) Backfill(ctx context.Context, ls *certstream.LogStream) {
	go cdb.backfillGaps(ctx, ls)
	row := cdb.QueryRowContext(ctx, setPrefix(SelectMinIndex), ls.Id)
	var minIndex int64
	if err := row.Scan(&minIndex); cdb.LogError(err, "Backfill/MinIndex", "url", ls.URL) == nil {
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
