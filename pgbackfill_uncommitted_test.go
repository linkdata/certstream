package certstream

import "testing"

func TestGapScanRetriesUncommittedFetchedEntry(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/uncommitted-gap", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2}); err != nil {
		t.Fatal(err)
	}
	// A fetched entry waits in the DB queue while the scanner records progress.
	// The next scan must retry it if the queue never commits that entry.
	first, _ := newTileTestStream(t, 3)
	first.CertStream = cs
	first.Id = streamID
	first.LastIndex.Store(2)
	if err := db.scanAndBackfillGaps(ctx, first, first.getGapEntries); err != nil {
		t.Fatal(err)
	}
	if first.Count.Load() != 1 {
		t.Fatalf("first fetch count = %d, want 1", first.Count.Load())
	}
	queued := 0
	for _, ch := range db.batchCh {
		queued += len(ch)
	}
	if queued != 1 {
		t.Fatalf("queued entries = %d, want 1", queued)
	}
	var exists bool
	if err := db.QueryRow(ctx, db.Pfx(`SELECT EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1)`), streamID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("gap entry committed unexpectedly")
	}
	second, _ := newTileTestStream(t, 3)
	second.CertStream = cs
	second.Id = streamID
	second.LastIndex.Store(2)
	if err := db.scanAndBackfillGaps(ctx, second, second.getGapEntries); err != nil {
		t.Fatal(err)
	}
	if second.Count.Load() != 1 {
		t.Fatalf("retry fetch count = %d, want 1", second.Count.Load())
	}
}
