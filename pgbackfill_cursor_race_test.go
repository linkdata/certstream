package certstream

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestGapCursorDoesNotOutrunVerifiedMax(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	const url = "https://example.test/cursor-race"
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID, log: &loglist3.Log{URL: url}}
	ls.LastIndex.Store(20)
	if err := insertEntries(ctx, db, streamID, []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}); err != nil {
		t.Fatal(err)
	}
	if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
		t.Fatal(err)
	}
	// A live scan and its consumer issue independent MAX queries. This ordering
	// lets the scan finish while head ingestion commits a later, incomplete range.
	ls.gapCh = make(chan gap, 1)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{11, 12, 13, 14, 16, 17, 18, 19, 20}); err != nil {
		t.Fatal(err)
	}
	if err := db.backfillGapsWithFetcher(ctx, ls, func(context.Context, int64, int64, bool, handleLogEntryFn, *atomic.Int64) (int64, bool) {
		t.Fatal("unexpected fetch")
		return 0, false
	}, nil); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 10 {
		t.Fatalf("cursor = %d, want scanned max 10", cursor)
	}
	ls.gapCh = make(chan gap, 1)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if got := collectGaps(ls.gapCh); !gapsEqual(got, []gap{{15, 15}}) {
		t.Fatalf("rescan gaps = %v, want [{15 15}]", got)
	}
}
