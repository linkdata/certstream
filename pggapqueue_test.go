package certstream

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestPgDB_QueueGapReservation(t *testing.T) {
	db := &PgDB{}
	ls := &LogStream{}
	gapCh := make(chan gap, 2)
	for _, g := range []gap{{start: 2, end: 3}, {start: 5, end: 7}} {
		if err := db.queueGap(t.Context(), ls, gapCh, g, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := ls.Backfill.Load(); got != 5 {
		t.Fatalf("queued backfill = %d, want 5", got)
	}
	if err := db.queueGap(t.Context(), ls, gapCh, gap{start: 9, end: 9}, true); !errors.Is(err, errGapChannelFull) || errors.Is(err, errGapScanDeferred) {
		t.Fatalf("full channel error = %v, want scan deferred", err)
	}
	if got := ls.Backfill.Load(); got != 5 {
		t.Fatalf("backfill after full channel = %d, want 5", got)
	}
	if got := db.gaps[ls.Id]; got.gaps != 2 || got.entries != 5 {
		t.Fatalf("recorded gaps = %+v, want 2 gaps and 5 entries", got)
	}

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		waiting := &LogStream{}
		unbuffered := make(chan gap)
		done := make(chan error, 1)
		go func() {
			done <- db.queueGap(ctx, waiting, unbuffered, gap{start: 10, end: 12}, false)
		}()
		synctest.Wait()
		if got := waiting.Backfill.Load(); got != 3 {
			t.Fatalf("blocked send backfill = %d, want 3", got)
		}
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled send error = %v, want context canceled", err)
		}
		if got := waiting.Backfill.Load(); got != 0 {
			t.Fatalf("backfill after canceled send = %d, want 0", got)
		}
	})
}

func TestPgDB_BackfillEstimateCountsQueuedGapsOnce(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	url := "https://example.test/queued-gap-estimate"
	if err := insertStream(ctx, db, url, operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{1, 3, 5}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		log:         &loglist3.Log{URL: url},
	}
	ls.LastIndex.Store(-1)
	ls.Backfill.Store(7) // An independent reverse backfill can share the counter.
	if err := db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
		t.Fatal(err)
	}

	var fetched []gap
	fetch := func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		fetched = append(fetched, gap{start: start, end: end})
		remaining.Add(-(end - start + 1))
		return end + 1, true
	}
	want := []gap{{start: 2, end: 2}, {start: 4, end: 4}}
	for attempt := 1; attempt <= 2; attempt++ {
		ls.gapCh = make(chan gap, 8)
		if err := db.selectStreamGaps(ctx, ls); err != nil {
			t.Fatal(err)
		}
		if got := ls.Backfill.Load(); got != 9 {
			t.Fatalf("attempt %d queued backfill = %d, want 9", attempt, got)
		}
		fetched = nil
		if err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false); err != nil {
			t.Fatal(err)
		}
		if !gapsEqual(fetched, want) {
			t.Fatalf("attempt %d fetched = %v, want %v", attempt, fetched, want)
		}
		if got := ls.Backfill.Load(); got != 7 {
			t.Fatalf("attempt %d backfill after fetch = %d, want 7", attempt, got)
		}
	}

	ls.gapCh = make(chan gap, 8)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if got := ls.Backfill.Load(); got != 9 {
		t.Fatalf("queued backfill before cancellation = %d, want 9", got)
	}
	fetched = nil
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := db.backfillGapsWithFetcherMode(canceled, ls, fetch, nil, false); err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 0 {
		t.Fatalf("fetched after cancellation = %v, want none", fetched)
	}
	if got := ls.Backfill.Load(); got != 7 {
		t.Fatalf("backfill after canceled fetch = %d, want 7", got)
	}
}
