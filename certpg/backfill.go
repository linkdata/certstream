package certpg

import (
	"context"

	ct "github.com/google/certificate-transparency-go"
	"github.com/linkdata/certstream"
)

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
	cdb.backfillGaps(ctx, ls)
	// maybe start working towards the beginning of the stream at low priority
}
