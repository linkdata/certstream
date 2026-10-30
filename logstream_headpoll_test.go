package certstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/tls"
)

type headPollTransport struct {
	head         atomic.Int64
	failHead     atomic.Bool
	failEntries  atomic.Bool
	headRequests atomic.Int64
	entries      atomic.Int64
	entryPayload []byte
	signature    []byte
	headHeader   http.Header
	entryStarts  chan string
	blockCall    int64
	releaseEntry chan struct{}
}

func newHeadPollTransport(t testing.TB) *headPollTransport {
	t.Helper()
	entry := makeTestLeafEntry(t, time.Now().UTC().Truncate(time.Millisecond))
	payload, err := json.Marshal(ct.GetEntriesResponse{Entries: []ct.LeafEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := tls.Marshal(tls.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
		Signature: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &headPollTransport{
		entryPayload: payload,
		signature:    signature,
		entryStarts:  make(chan string, 8),
	}
}

func (tr *headPollTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	var payload []byte
	header := make(http.Header)
	switch req.URL.Path {
	case "/ct/v1/get-sth":
		tr.headRequests.Add(1)
		if tr.failHead.Load() {
			return nil, io.ErrNoProgress
		}
		if tr.headHeader != nil {
			header = tr.headHeader.Clone()
		}
		payload, err = json.Marshal(ct.GetSTHResponse{
			TreeSize:          uint64(tr.head.Load() + 1), // #nosec G115 -- fixture heads are at least -1
			Timestamp:         uint64(time.Now().UnixMilli()),
			SHA256RootHash:    make([]byte, 32),
			TreeHeadSignature: tr.signature,
		})
	case "/ct/v1/get-entries":
		call := tr.entries.Add(1)
		select {
		case tr.entryStarts <- req.URL.Query().Get("start"):
		default:
		}
		if tr.failEntries.Load() {
			return nil, io.ErrNoProgress
		}
		if call == tr.blockCall && tr.releaseEntry != nil {
			select {
			case <-tr.releaseEntry:
			case <-req.Context().Done():
				err = req.Context().Err()
			}
		}
		payload = tr.entryPayload
	default:
		err = fmt.Errorf("unexpected CT path %q", req.URL.Path)
	}
	if err == nil {
		resp = &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Request:    req,
		}
	}
	return
}

func newHeadPollStream(t testing.TB, tr *headPollTransport) *LogStream {
	t.Helper()
	const url = "https://headpoll.example.test/"
	cs := &CertStream{
		Config:      Config{Concurrency: 2},
		HeadClient:  &http.Client{Transport: tr},
		sendEntryCh: make(chan *LogEntry, 16),
		operators:   make(map[string]*LogOperator),
	}
	lo := &LogOperator{CertStream: cs, Domain: OperatorDomain(url), streams: make(map[string]*LogStream)}
	ls, err := lo.makeStream(&loglist3.Log{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	lo.streams[url] = ls
	cs.operators[lo.Domain] = lo
	return ls
}

func startHeadPollStream(t *testing.T, tr *headPollTransport) *LogStream {
	t.Helper()
	ls := newHeadPollStream(t, tr)
	ctx, cancel := context.WithCancel(t.Context())
	ls.cancel = cancel
	ls.done = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go ls.run(ctx, &wg)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return ls
}

func TestHeadAdvancesDuringEntryFetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newHeadPollTransport(t)
		tr.head.Store(0)
		tr.blockCall = 2 // getEndSeen reads the first entry before the reader starts.
		tr.releaseEntry = make(chan struct{})
		ls := startHeadPollStream(t, tr)
		synctest.Wait()
		if got := tr.entries.Load(); got != 2 {
			t.Fatalf("entry requests before head advances = %d; want 2", got)
		}
		tr.head.Store(1)
		time.Sleep(12 * time.Second)
		synctest.Wait()
		if got := ls.LastIndex.Load(); got != 1 {
			t.Fatalf("LastIndex = %d while entry fetch is blocked; want 1", got)
		}
		if got := ls.MaxIndex.Load(); got != 0 {
			t.Fatalf("MaxIndex = %d while entry fetch is blocked; want 0", got)
		}
		tr.head.Store(0)
		time.Sleep(12 * time.Second)
		synctest.Wait()
		if got := ls.LastIndex.Load(); got != 1 {
			t.Fatalf("LastIndex = %d after stale head; want 1", got)
		}
		close(tr.releaseEntry)
		synctest.Wait()
		for _, want := range []string{"0", "0", "1"} {
			select {
			case got := <-tr.entryStarts:
				if got != want {
					t.Fatalf("entry fetch start = %q; want %q", got, want)
				}
			default:
				t.Fatalf("entry fetch from %s did not start", want)
			}
		}
	})
}

func TestRunWaitsForFirstNonnegativeHead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newHeadPollTransport(t)
		tr.head.Store(-1)
		ls := startHeadPollStream(t, tr)
		synctest.Wait()
		if got := tr.headRequests.Load(); got != 1 {
			t.Fatalf("initial head requests = %d; want 1", got)
		}
		if got := ls.LastIndex.Load(); got != -1 {
			t.Fatalf("LastIndex = %d for empty tree; want -1", got)
		}
		if got := tr.entries.Load(); got != 0 {
			t.Fatalf("entry requests = %d before first head; want 0", got)
		}
		tr.head.Store(0)
		time.Sleep(12 * time.Second)
		synctest.Wait()
		if got := ls.LastIndex.Load(); got != 0 {
			t.Fatalf("LastIndex = %d for one-entry tree; want 0", got)
		}
		if got := tr.entries.Load(); got == 0 {
			t.Fatal("reader did not start at head index 0")
		}
	})
}

func TestHeadPollRespectsCacheFreshness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newHeadPollTransport(t)
		tr.head.Store(0)
		tr.headHeader = make(http.Header)
		tr.headHeader.Set("Cache-Control", "public, max-age=30")
		tr.headHeader.Set("Age", "10")
		startHeadPollStream(t, tr)
		synctest.Wait()
		if got := tr.headRequests.Load(); got != 1 {
			t.Fatalf("initial head requests = %d; want 1", got)
		}
		time.Sleep(19 * time.Second)
		synctest.Wait()
		if got := tr.headRequests.Load(); got != 1 {
			t.Fatalf("head requests before cache expiry = %d; want 1", got)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if got := tr.headRequests.Load(); got < 2 {
			t.Fatalf("head requests after cache expiry = %d; want at least 2", got)
		}
	})
}

func TestHeadPollFailureStopsActiveReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newHeadPollTransport(t)
		tr.head.Store(0)
		ls := startHeadPollStream(t, tr)
		synctest.Wait()
		if got := tr.entries.Load(); got != 2 {
			t.Fatalf("entry requests before head failure = %d; want 2", got)
		}
		tr.failHead.Store(true)
		time.Sleep(12 * time.Second)
		synctest.Wait()
		select {
		case <-ls.done:
		default:
			t.Fatal("stream did not stop after terminal head error")
		}
	})
}

func TestReaderWaitsAfterNoProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newHeadPollTransport(t)
		tr.failEntries.Store(true)
		ls := newHeadPollStream(t, tr)
		ls.LastIndex.Store(0)
		ctx, cancel := context.WithCancel(t.Context())
		var wg sync.WaitGroup
		wg.Add(1)
		go ls.readEntries(ctx, 0, &wg)
		defer func() {
			cancel()
			wg.Wait()
		}()
		synctest.Wait()
		time.Sleep(9 * time.Second)
		synctest.Wait()
		if got := tr.entries.Load(); got != 1 {
			t.Fatalf("entry requests before retry delay = %d; want 1", got)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if got := tr.entries.Load(); got < 2 {
			t.Fatalf("entry requests after retry delay = %d; want at least 2", got)
		}
	})
}
