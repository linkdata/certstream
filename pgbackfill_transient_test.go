package certstream

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
)

func TestReverseBackfillRetriesFatalHTTPWindow(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	var opID, streamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ('op', 'op@example.com') RETURNING id`)).Scan(&opID); err != nil {
		t.Fatal(err)
	}
	leaf := makeTestLeafEntry(t, time.Now())
	good, err := json.Marshal(ct.GetEntriesResponse{Entries: []ct.LeafEntry{leaf}})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/v1/get-entries" {
			http.NotFound(w, r)
			return
		}
		n := calls.Add(1)
		// A CT server may return fewer entries than requested. The failure
		// after that partial response must retry only the remaining index.
		if n <= 99 || n == 101 {
			if _, err := w.Write([]byte("{")); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := w.Write(good); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	if err := insertStream(ctx, db, server.URL, opID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{2}); err != nil {
		t.Fatal(err)
	}
	logClient, err := client.New(server.URL, server.Client(), jsonclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	lo := &LogOperator{CertStream: cs}
	ls := &LogStream{LogOperator: lo, Id: streamID, log: &loglist3.Log{URL: server.URL}, tailClient: logClient,
		backoff: newLogStreamBackoff(time.Second, 30*time.Second, 2, true)}
	ls.LastIndex.Store(2)
	for range 99 {
		_, e := logClient.GetRawEntries(ctx, 0, 1)
		if e == nil || ls.handleStreamError(e, "GetRawEntries") {
			t.Fatalf("prior error %d: %v", calls.Load(), e)
		}
	}
	scanCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go db.backfillStream(scanCtx, ls, &wg)
	defer func() { cancel(); wg.Wait() }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for ls.Count.Load() != 2 || ls.Backfill.Load() != 0 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("reverse backfill sent %d of 2 entries after %d HTTP calls", ls.Count.Load(), calls.Load())
		}
	}
	if calls.Load() != 102 {
		t.Fatalf("HTTP calls=%d, want 102", calls.Load())
	}
	for _, entry := range lo.Errors() {
		if errors.Is(entry.Err, ErrLogEntriesTooOld) {
			t.Fatal("transient HTTP failure reported as entries too old")
		}
	}
	queued := 0
	for _, ch := range db.batchCh {
		queued += len(ch)
	}
	if queued != 2 {
		t.Fatalf("queued entries=%d, want 2", queued)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id=$1`), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("cursor=%d, want 2", cursor)
	}
}
