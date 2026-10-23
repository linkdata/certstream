package certstream

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestEmptyDBStartupBackfillsFromKnownHead(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var operatorID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.test/", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	ls, _ := newTileTestStream(t, 4)
	ls.CertStream = cs
	ls.Id = streamID
	ls.tiledLog = &loglist3.TiledLog{MonitoringURL: "https://example.test/"}
	ls.LastIndex.Store(3)
	scanCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go db.backfillStream(scanCtx, ls, &wg)
	defer wg.Wait()
	defer cancel()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for ls.Count.Load() != 4 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("backfill sent %d of 4 entries from known head into empty DB", ls.Count.Load())
		}
	}
}
