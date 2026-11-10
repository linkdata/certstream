package certstream

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/jackc/pgx/v5/pgconn"
)

func installShardIngestProbe(t *testing.T, db *PgDB, failedShard int) {
	t.Helper()
	const probe = `
CREATE TABLE CERTDB_test_shard_calls (shard integer NOT NULL, entries integer NOT NULL);
CREATE FUNCTION CERTDB_test_shard_ingest(_rows jsonb, _bits integer, _failed integer)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  first_shard integer;
  last_shard integer;
  entry_count integer;
BEGIN
  SELECT min(shard), max(shard), count(*) INTO first_shard, last_shard, entry_count
  FROM (
    SELECT get_byte(decode(row->>'sha256_hex', 'hex'), 0) >> (8 - _bits) AS shard
    FROM jsonb_array_elements(_rows) AS row
  ) AS entries;
  IF first_shard IS DISTINCT FROM last_shard THEN
    RAISE EXCEPTION 'mixed SHA prefixes in one ingest call';
  END IF;
  IF first_shard = _failed THEN
    RAISE EXCEPTION 'test shard failure' USING ERRCODE = '22012';
  END IF;
  INSERT INTO CERTDB_test_shard_calls (shard, entries) VALUES (first_shard, entry_count);
  PERFORM CERTDB_ingest_batch(_rows);
END;
$$;`
	if _, err := db.Exec(t.Context(), db.Pfx(probe)); err != nil {
		t.Fatal(err)
	}
	original := db.funcIngestBatch
	t.Cleanup(func() { db.funcIngestBatch = original })
	db.funcIngestBatch = db.Pfx(fmt.Sprintf(`SELECT CERTDB_test_shard_ingest($1::jsonb, %d, %d)`, db.workerBits, failedShard))
}

func TestRunGapBatchesKeepsSHAPrefixesSeparate(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	installShardIngestProbe(t, db, -1)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	entries := make([]*LogEntry, 256)
	want := make(map[int]int)
	for i := range entries {
		entries[i] = retentionEntry(t, ls, int64(i), time.Now().UTC().Add(time.Hour))
		want[db.workerIndexFor(entries[i])]++
	}
	stored, err := db.runGapBatches(ctx, entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, ok := range stored {
		if !ok {
			t.Fatalf("entry %d was not stored", i)
		}
	}
	rows, err := db.Query(ctx, db.Pfx(`SELECT shard, entries FROM CERTDB_test_shard_calls`))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := make(map[int]int)
	for rows.Next() {
		var shard, count int
		if err := rows.Scan(&shard, &count); err != nil {
			t.Fatal(err)
		}
		got[shard] += count
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("ingested %d SHA prefixes, want %d", len(got), len(want))
	}
	for shard, count := range want {
		if got[shard] != count {
			t.Errorf("shard %d stored %d entries, want %d", shard, got[shard], count)
		}
	}
}

func TestGapTilePartialShardFailureKeepsCursorAndCounts(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	if err := insertEntries(ctx, db, streamID, []int64{0, 4}); err != nil {
		t.Fatal(err)
	}
	cs.sendEntryCh = make(chan *LogEntry, 3)
	ls := &LogStream{
		LogOperator: &LogOperator{CertStream: cs},
		Id:          streamID,
		tiledLog:    &loglist3.TiledLog{MonitoringURL: "https://example.test/"},
	}
	ls.LastIndex.Store(4)
	queueTestGaps(ls, []gap{{1, 3}})
	entries := make(map[int64]*LogEntry)
	used := make(map[int]bool)
	for index := int64(1); index <= 3; index++ {
		for attempt := 0; attempt < 256 && entries[index] == nil; attempt++ {
			entry := retentionEntry(t, ls, index, time.Now().UTC().Add(time.Hour))
			shard := db.workerIndexFor(entry)
			if !used[shard] {
				used[shard] = true
				entries[index] = entry
			}
		}
		if entries[index] == nil {
			t.Fatalf("could not make entry %d in a distinct SHA shard", index)
		}
	}
	installShardIngestProbe(t, db, db.workerIndexFor(entries[2]))
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		for index := start; index <= end; index++ {
			handle(ctx, time.Now(), entries[index])
			remaining.Add(-1)
		}
		return end + 1, true
	}
	err := db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22012" {
		t.Fatalf("backfill error = %v, want test shard failure", err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("durable cursor = %d, want failed index 2", cursor)
	}
	var first, failed, last bool
	if err := db.QueryRow(ctx, db.Pfx(`SELECT
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 2),
EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 3)`), streamID).Scan(&first, &failed, &last); err != nil {
		t.Fatal(err)
	}
	if !first || failed || !last {
		t.Fatalf("stored entries = (%t, %t, %t), want (true, false, true)", first, failed, last)
	}
	if got := ls.Count.Load(); got != 2 {
		t.Errorf("stream count = %d, want 2 committed entries", got)
	}
	if got := ls.LogOperator.Count.Load(); got != 2 {
		t.Errorf("operator count = %d, want 2 committed entries", got)
	}
	for _, want := range []int64{1, 3} {
		select {
		case entry := <-cs.sendEntryCh:
			if entry.LogIndex != want {
				t.Errorf("published index = %d, want %d", entry.LogIndex, want)
			}
		default:
			t.Errorf("missing published entry %d", want)
		}
	}
	select {
	case entry := <-cs.sendEntryCh:
		t.Errorf("unexpected published entry %d", entry.LogIndex)
	default:
	}
}
