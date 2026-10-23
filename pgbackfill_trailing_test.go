package certstream

import (
	"context"
	"sync/atomic"
	"testing"
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
	if !gapsEqual(got, []gap{{3, 5}}) {
		t.Fatalf("stationary uncommitted tail fetched %v, want [{3 5}]", got)
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
	if !gapsEqual(got, []gap{{3, 5}, {4, 10_003}}) {
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
	if !gapsEqual(got, []gap{{100, 102}}) {
		t.Fatalf("empty DB trailing recovery = %v, want [{100 102}]", got)
	}
}
