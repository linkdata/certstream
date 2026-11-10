package certstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestGapScanCommitsFetchedEntryAndAdvancesCursor(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/committed-gap", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2}); err != nil {
		t.Fatal(err)
	}
	// Gap ingestion commits before the cursor advances, without a batch worker.
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
	if queued != 0 {
		t.Fatalf("queued entries = %d, want 0", queued)
	}
	var exists bool
	if err := db.QueryRow(ctx, db.Pfx(`SELECT EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1)`), streamID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("gap entry was not committed")
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("backfill_logindex = %d, want 2", cursor)
	}
	second, _ := newTileTestStream(t, 3)
	second.CertStream = cs
	second.Id = streamID
	second.LastIndex.Store(2)
	if err := db.scanAndBackfillGaps(ctx, second, second.getGapEntries); err != nil {
		t.Fatal(err)
	}
	if second.Count.Load() != 0 {
		t.Fatalf("second scan fetched %d entries, want 0", second.Count.Load())
	}
}

func TestGapScanCommitsUnparseableLeafAndAdvancesCursor(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/unparseable-gap", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{0, 2}); err != nil {
		t.Fatal(err)
	}
	cs.sendEntryCh = make(chan *LogEntry, 1)
	ls, transport := newTileTestStream(t, 3)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(2)
	bad := *transport.entries[1]
	bad.Certificate = mismatchedSignatureAlgorithm(t, bad.Certificate)
	check := ls.makeTileLogEntry(1, &bad, true)
	if check.Err == nil || check.Certificate != nil || !bytes.Equal(check.rawCert, bad.Certificate) {
		t.Fatalf("unparseable leaf = (err %v, cert %v, raw %d bytes)", check.Err, check.Certificate, len(check.rawCert))
	}
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		for index := start; index <= end; index++ {
			entry := transport.entries[index]
			if index == 1 {
				entry = &bad
			}
			handle(ctx, time.Now(), ls.makeTileLogEntry(index, entry, true))
			remaining.Add(-1)
		}
		return end + 1, true
	}
	if err := db.scanAndBackfillGaps(ctx, ls, fetch); err != nil {
		t.Fatal(err)
	}
	if got := ls.Backfill.Load(); got != 0 {
		t.Fatalf("Backfill = %d, want 0", got)
	}
	if got := len(cs.sendEntryCh); got != 0 {
		t.Fatalf("published unparseable entries = %d, want 0", got)
	}
	var certID int64
	var seen time.Time
	if err := db.QueryRow(ctx, db.Pfx(`SELECT cert, seen FROM CERTDB_entry WHERE stream = $1 AND logindex = 1`), streamID).Scan(&certID, &seen); err != nil {
		t.Fatal(err)
	}
	if certID != 0 {
		t.Fatalf("cert = %d, want marker 0", certID)
	}
	var badSeen time.Time
	var name string
	var raw, hash []byte
	if err := db.QueryRow(ctx, db.Pfx(`SELECT seen, commonname, rawcert, sha256 FROM CERTDB_badcert WHERE stream = $1 AND logindex = 1`), streamID).Scan(&badSeen, &name, &raw, &hash); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(bad.Certificate)
	if !badSeen.Equal(seen) || name != "example.test" || !bytes.Equal(raw, bad.Certificate) || !bytes.Equal(hash, wantHash[:]) {
		t.Fatalf("badcert = (seen %v, name %q, raw %d bytes, hash %x)", badSeen, name, len(raw), hash)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("backfill_logindex = %d, want 2", cursor)
	}
}

func TestGapScanDoesNotAdvancePastFailedBatch(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/failed-gap-batch", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 258) AS n WHERE n NOT IN (1, 257)`), streamID); err != nil {
		t.Fatal(err)
	}
	cs.sendEntryCh = make(chan *LogEntry, 2)
	ls, _ := newTileTestStream(t, 259)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(258)

	goodQuery := db.funcIngestBatch
	db.funcIngestBatch = `SELECT 1/0 WHERE $1::jsonb IS NOT NULL`
	t.Cleanup(func() { db.funcIngestBatch = goodQuery })
	fetch := func(ctx context.Context, start, end int64, historical bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		if start == 256 {
			db.funcIngestBatch = goodQuery
		}
		return ls.getGapEntries(ctx, start, end, historical, handle, remaining)
	}
	err := db.scanAndBackfillGaps(ctx, ls, fetch)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22012" {
		t.Fatalf("scan error = %v, want division by zero", err)
	}
	var firstExists, laterExists bool
	if err := db.QueryRow(ctx, db.Pfx(`SELECT EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 257)`), streamID).Scan(&firstExists, &laterExists); err != nil {
		t.Fatal(err)
	}
	if firstExists || !laterExists {
		t.Fatalf("stored gaps: first=%t, later=%t; want false, true", firstExists, laterExists)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 1 {
		t.Fatalf("backfill_logindex = %d, want first missing index 1", cursor)
	}
	if got := ls.Count.Load(); got != 1 {
		t.Fatalf("published entry count = %d, want only the committed gap", got)
	}
	if got := ls.LogOperator.Count.Load(); got != 1 {
		t.Fatalf("operator published entry count = %d, want only the committed gap", got)
	}
	if got := <-cs.sendEntryCh; got.LogIndex != 257 {
		t.Fatalf("published index = %d, want 257", got.LogIndex)
	}
	select {
	case extra := <-cs.sendEntryCh:
		t.Fatalf("unexpected published entry: %d", extra.LogIndex)
	default:
	}
}
