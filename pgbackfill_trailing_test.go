package certstream

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestRecoverTrailingGapAfterFailedHeadBatch(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/missing-tail", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1, 2}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.LastIndex.Store(20_000)
	ls.MaxIndex.Store(5)
	var got []gap
	fetch := func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, counter *atomic.Int64) (int64, bool) {
		got = append(got, gap{start, end})
		counter.Add(-(end - start + 1))
		return end + 1, true
	}
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("first sample fetched %v", got)
	}
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if !gapsEqual(got, []gap{{0, 5}}) {
		t.Fatalf("stationary uncommitted tail fetched %v, want [{0 5}]", got)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream) VALUES ($1, $2, $3)`), 1003, 3, streamID); err != nil {
		t.Fatal(err)
	}
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("moving DB max fetched again: %v", got)
	}
	// A failed batch can leave the maximum unchanged while the source head moves.
	ls.LastIndex.Store(20_000)
	ls.MaxIndex.Store(20_000)
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if !gapsEqual(got, []gap{{0, 5}, {0, 10_239}}) {
		t.Fatalf("moving source head with stalled DB max fetched %v", got)
	}
}

func TestRecoverTrailingGapWhenFirstBatchFailed(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/empty-tail", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.MinIndex.Store(100)
	ls.MaxIndex.Store(102)
	var got []gap
	fetch := func(_ context.Context, start, end int64, _ bool, _ handleLogEntryFn, counter *atomic.Int64) (int64, bool) {
		got = append(got, gap{start, end})
		counter.Add(-(end - start + 1))
		return end + 1, true
	}
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if !gapsEqual(got, []gap{{0, 102}}) {
		t.Fatalf("empty DB trailing recovery = %v, want [{0 102}]", got)
	}
}

func TestRecoverTrailingGapFiltersAlignedPrefix(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/aligned-tail", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 1, 2}); err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	ls.MaxIndex.Store(3)
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		if start != 0 || end != 3 {
			t.Fatalf("aligned tail = %d..%d, want 0..3", start, end)
		}
		for index := start; index <= end; index++ {
			handle(ctx, time.Now(), &LogEntry{LogStream: ls, LogIndex: index, Err: errors.New("invalid test leaf")})
			remaining.Add(-1)
		}
		return end + 1, true
	}
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if err := db.recoverTrailingGap(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if got := len(db.batchCh[0]); got != 1 {
		t.Fatalf("queued entries = %d, want only missing index 3", got)
	}
	if got := (<-db.batchCh[0]).LogIndex; got != 3 {
		t.Fatalf("queued index = %d, want 3", got)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
}

func TestRecoverTrailingGapReleasesTileCache(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/tiled-tail", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0}); err != nil {
		t.Fatal(err)
	}
	ls, transport := newTileTestStream(t, 3)
	ls.LogOperator = &LogOperator{CertStream: cs}
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.MaxIndex.Store(2)
	if err := db.recoverTrailingGap(ctx, ls, ls.getGapEntries); err != nil {
		t.Fatal(err)
	}
	if err := db.recoverTrailingGap(ctx, ls, ls.getGapEntries); err != nil {
		t.Fatal(err)
	}
	if got := transport.dataTileCalls.Load(); got != 1 {
		t.Fatalf("data tile requests = %d, want 1", got)
	}
	if ls.gapRead.reader != nil || ls.gapRead.entries != nil {
		t.Fatal("trailing gap tile cache retained after fetch")
	}
}
