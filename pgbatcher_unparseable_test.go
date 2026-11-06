package certstream

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"filippo.io/sunlight"
)

func mismatchedSignatureAlgorithm(t *testing.T, der []byte) []byte {
	t.Helper()
	oid := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02} // ecdsa-with-SHA256
	if got := bytes.Count(der, oid); got != 2 {
		t.Fatalf("signature algorithm OID occurs %d times, want 2", got)
	}
	der = bytes.Clone(der)
	der[bytes.LastIndex(der, oid)+len(oid)-1] = 0x03 // ecdsa-with-SHA384 in outer field
	return der
}

func TestUnparseableCertificatesCloseGaps(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	if err := insertEntries(ctx, db, streamID, []int64{0, 2, 4}); err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	cs.sendEntryCh = make(chan *LogEntry, 2)
	cs.mu.Unlock()
	workerCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go db.worker(workerCtx, &wg, 0)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	now := time.Now().UTC().Truncate(time.Millisecond)
	classic := makeTestLeafEntry(t, now)
	classic.LeafInput = mismatchedSignatureAlgorithm(t, classic.LeafInput)
	entries := []*LogEntry{
		ls.makeLogEntry(1, classic, true),
		ls.makeTileLogEntry(3, &sunlight.LogEntry{
			Certificate: mismatchedSignatureAlgorithm(t, makeTestCertificate(t, now)),
			Timestamp:   now.UnixMilli(),
		}, true),
	}
	for _, le := range entries {
		if le.Err == nil || le.Certificate != nil {
			t.Fatalf("entry %d = (certificate %v, err %v), want parse error", le.LogIndex, le.Certificate, le.Err)
		}
		if !ls.sendEntry(ctx, now, le) {
			t.Fatalf("entry %d was not handled", le.LogIndex)
		}
	}
	for range 2 {
		ack := make(chan struct{}, 1)
		select {
		case db.batchCh[0] <- &LogEntry{flushAck: ack}:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case <-ack:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	select {
	case le := <-cs.getSendEntryCh():
		t.Fatalf("unparseable entry published to consumers: %v", le)
	default:
	}
	for _, index := range []int64{1, 3} {
		var certID int64
		var seen time.Time
		if err := db.QueryRow(ctx, db.Pfx(`SELECT cert, seen FROM CERTDB_entry WHERE stream = $1 AND logindex = $2`), streamID, index).Scan(&certID, &seen); err != nil {
			t.Fatal(err)
		}
		if certID != 0 || !seen.Equal(now.Truncate(time.Second)) {
			t.Fatalf("entry %d = (cert %d, seen %v), want marker at %v", index, certID, seen, now.Truncate(time.Second))
		}
	}
	if gaps, err := db.storedGaps(ctx, streamID, 0, 4); err != nil {
		t.Fatal(err)
	} else if len(gaps) != 0 {
		t.Fatalf("stored gaps = %v, want none", gaps)
	}
	ls.gapCh = make(chan gap, 1)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 4 {
		t.Fatalf("backfill_logindex = %d, want 4", cursor)
	}
}
