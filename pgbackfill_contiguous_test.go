package certstream

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestBackfillContiguousTilesCommitBeforeFetchCompletes(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/contiguous-gap-commit", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream)
SELECT n + 1000, n, $1 FROM generate_series(0, 511) AS n WHERE n NOT BETWEEN 250 AND 510`), streamID); err != nil {
		t.Fatal(err)
	}
	ls, transport := newTileTestStream(t, 512)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(511)
	if err := db.backfillSetGapStartIndex(ctx, ls, 250); err != nil {
		t.Fatal(err)
	}
	ls.gapCh = make(chan gap, 1)
	ls.gapCh <- gap{start: 250, end: 510}
	close(ls.gapCh)
	ls.Backfill.Store(261)

	paused := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var fetched []gap
	fetch := func(ctx context.Context, start, end int64, _ bool, handle handleLogEntryFn, remaining *atomic.Int64) (int64, bool) {
		fetched = append(fetched, gap{start: start, end: end})
		for index := start; index <= end; index++ {
			handle(ctx, time.Now(), ls.makeTileLogEntry(index, transport.entries[index], true))
			remaining.Add(-1)
			if index == 256 {
				close(paused)
				select {
				case <-release:
				case <-ctx.Done():
					return index + 1, false
				}
			}
		}
		return end + 1, true
	}
	done := make(chan error, 1)
	go func() { done <- db.backfillGapsWithFetcherMode(ctx, ls, fetch, nil, false) }()
	finished := false
	defer func() {
		unblock()
		if !finished {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("backfill cleanup: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("backfill did not stop")
			}
		}
	}()
	select {
	case <-paused:
	case <-time.After(10 * time.Second):
		t.Fatal("fetch did not reach the second tile")
	}
	select {
	case err := <-done:
		finished = true
		t.Fatalf("backfill finished while fetch was paused: %v", err)
	default:
	}
	var firstTileCount, cursor int64
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		if err := db.QueryRow(ctx, db.Pfx(`SELECT
(SELECT count(*) FROM CERTDB_entry WHERE stream = $1 AND logindex BETWEEN 250 AND 255),
backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&firstTileCount, &cursor); err != nil {
			t.Fatal(err)
		}
		if firstTileCount == 6 && cursor == 256 {
			break
		}
		select {
		case err := <-done:
			finished = true
			t.Fatalf("backfill finished while fetch was paused: %v", err)
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("paused fetch: first tile rows = %d, cursor = %d; want 6 rows and cursor 256", firstTileCount, cursor)
		}
	}
	unblock()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backfill did not finish after fetch resumed")
	}
	if len(fetched) != 2 || fetched[0] != (gap{start: 250, end: 255}) || fetched[1] != (gap{start: 256, end: 510}) {
		t.Fatalf("fetch ranges = %v, want one request per tile", fetched)
	}
	var missing int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT count(*) FROM generate_series(250, 510) AS series(logindex)
WHERE NOT EXISTS (SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = series.logindex)`), streamID).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, db.Pfx(SelectBackfillIndex), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if missing != 0 || cursor != 511 || ls.Backfill.Load() != 0 {
		t.Fatalf("completed fetch: missing = %d, cursor = %d, Backfill = %d; want 0, 511, 0", missing, cursor, ls.Backfill.Load())
	}
}
