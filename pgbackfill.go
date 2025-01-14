package certstream

import (
	"context"
	"database/sql"
	"sync/atomic"

	ct "github.com/google/certificate-transparency-go"
)

var BulkRange = int64(4096)

func (cdb *PgDB) backfillGaps(ctx context.Context, ls *LogStream, gapcounter *atomic.Int64) {
	type gap struct {
		start int64
		end   int64
	}
	var gaps []gap
	if rows, err := cdb.Query(ctx, cdb.stmtSelectGaps, ls.Id); cdb.LogError(err, "backfillGaps/Query", "url", ls.URL) == nil {
		for rows.Next() {
			var gap_start, gap_end int64
			if err = rows.Scan(&gap_start, &gap_end); cdb.LogError(err, "backfillGaps/Scan", "url", ls.URL) == nil {
				gaps = append(gaps, gap{start: gap_start, end: gap_end})
			}
			gapcounter.Add((gap_end - gap_start) + 1)
		}
		rows.Close()
	}
	if lastindex := ls.LastIndex.Load(); lastindex != -1 {
		row := cdb.QueryRow(ctx, cdb.stmtSelectMaxIdx, ls.Id)
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
			gapcounter.Add(-1)
			_ = cdb.Entry(ctx, ls.MakeLogEntry(logindex, entry, true))
		})
	}
}

func (cdb *PgDB) backfillStream(ctx context.Context, ls *LogStream) {
	gapcounter := &ls.InsideGaps
	if ls2, err := NewLogStream(ls.LogOperator, cdb.cdb.TailClient, ls.Log); cdb.LogError(err, "BackfillStream", "url", ls.URL) == nil {
		ls2.Id = ls.Id
		ls2.LastIndex.Store(ls.LastIndex.Load())
		ls2.backfilled.Store(true)
		ls = ls2
		cdb.backfillGaps(ctx, ls, gapcounter)
		row := cdb.QueryRow(ctx, cdb.stmtSelectMinIdx, ls.Id)
		var nullableMinIndex sql.NullInt64
		if err := cdb.LogError(row.Scan(&nullableMinIndex), "Backfill/MinIndex", "url", ls.URL); err == nil {
			if !nullableMinIndex.Valid {
				nullableMinIndex.Int64 = ls2.LastIndex.Load()
			}
			minIndex := nullableMinIndex.Int64
			if minIndex > 0 {
				if l := cdb.Logger; l != nil {
					l.Info("certstream: backlog", "url", ls.URL, "stream", ls.Id, "logindex", minIndex)
				}
				for minIndex > 0 {
					start := max(0, minIndex-BulkRange)
					stop := minIndex - 1
					ls.GetRawEntries(ctx, start, stop, func(logindex int64, entry ct.LeafEntry) {
						_ = cdb.Entry(ctx, ls.MakeLogEntry(logindex, entry, true))
					})
					minIndex = start
				}
			}
		}
	}
}
