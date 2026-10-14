package certstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/linkdata/bwlimit"
)

type pipeDialer struct{}

func (pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func testQueueStream(queue chan *LogEntry) *LogStream {
	cs := &CertStream{db: &PgDB{batchCh: []chan *LogEntry{queue}}}
	return &LogStream{LogOperator: &LogOperator{CertStream: cs}}
}

func TestWaitForQueueDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := make(chan *LogEntry, 2)
		queue <- &LogEntry{}
		queue <- &LogEntry{}
		ls := testQueueStream(queue)
		if err := ls.waitForQueue(t.Context(), false); err != nil {
			t.Fatalf("live stream wait: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- ls.waitForQueue(t.Context(), true) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("historical stream passed full queue: %v", err)
		default:
		}
		<-queue
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatalf("historical stream wait: %v", err)
		}
	})
}

func TestWaitForQueueCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := make(chan *LogEntry, 2)
		queue <- &LogEntry{}
		queue <- &LogEntry{}
		ls := testQueueStream(queue)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- ls.waitForQueue(ctx, true) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("historical stream wait error = %v, want context.Canceled", err)
		}
	})
}

func TestGetTileEntriesWaitsForQueueBeforeHTTP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ls, transport := newTileTestStream(t, 3)
		queue := make(chan *LogEntry, 2)
		queue <- &LogEntry{}
		queue <- &LogEntry{}
		ls.db = &PgDB{batchCh: []chan *LogEntry{queue}}
		type result struct {
			next   int64
			wanted bool
		}
		done := make(chan result, 1)
		go func() {
			next, wanted := ls.getTileEntries(t.Context(), 0, 0, true,
				func(context.Context, time.Time, *LogEntry) bool { return true }, nil)
			done <- result{next, wanted}
		}()
		synctest.Wait()
		if got := transport.requests.Load(); got != 0 {
			t.Fatalf("requests while queue full=%d, want 0", got)
		}
		<-queue
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if got := <-done; got.next != 1 || !got.wanted {
			t.Fatalf("next=%d wanted=%v", got.next, got.wanted)
		}
	})
}

func TestGetRawEntriesWaitsForQueueBeforeHTTP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := make(chan *LogEntry, 2)
		queue <- &LogEntry{}
		queue <- &LogEntry{}
		ls := testQueueStream(queue)
		client := &controlledRawEntriesClient{entry: makeTestLeafEntry(t, time.Now())}
		done := make(chan error, 1)
		go func() {
			_, _, err := ls.getRawEntries(t.Context(), client, 0, 0, true,
				func(context.Context, time.Time, *LogEntry) bool { return true }, nil)
			done <- err
		}()
		synctest.Wait()
		if got := len(client.Calls()); got != 0 {
			t.Fatalf("requests while queue full=%d, want 0", got)
		}
		<-queue
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatalf("getRawEntries: %v", err)
		}
	})
}

func TestGetTileEntriesWaitsBetweenEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ls, _ := newTileTestStream(t, 3)
		queue := make(chan *LogEntry, 2)
		ls.db = &PgDB{batchCh: []chan *LogEntry{queue}}
		var seen atomic.Int64
		done := make(chan int64, 1)
		go func() {
			next, _ := ls.getTileEntries(t.Context(), 0, 2, true,
				func(_ context.Context, _ time.Time, entry *LogEntry) bool {
					seen.Add(1)
					if entry.LogIndex == 0 {
						queue <- &LogEntry{}
						queue <- &LogEntry{}
					}
					return true
				}, nil)
			done <- next
		}()
		synctest.Wait()
		if got := seen.Load(); got != 1 {
			t.Fatalf("entries handled while queue full=%d, want 1", got)
		}
		<-queue
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if got := <-done; got != 3 {
			t.Fatalf("next=%d, want 3", got)
		}
		if got := seen.Load(); got != 3 {
			t.Fatalf("entries handled=%d, want 3", got)
		}
	})
}

func TestStartPreservesConfiguredTailLimiter(t *testing.T) {
	limiter := bwlimit.NewLimiter(1024)
	t.Cleanup(limiter.Stop)
	cfg := NewConfig()
	cfg.HeadDialer = noDialer{}
	cfg.TailDialer = limiter.Wrap(pipeDialer{})
	cfg.DataDir = ""
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	stream, err := Start(ctx, &wg, cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if stream.TailClient == nil {
		t.Fatal("tail client is nil")
	}
	counter, ok := stream.TailClient.Transport.(httpCallCounter)
	if !ok {
		t.Fatalf("tail transport has type %T", stream.TailClient.Transport)
	}
	transport, ok := counter.next.(*http.Transport)
	if !ok {
		t.Fatalf("tail inner transport has type %T", counter.next)
	}
	conn, err := transport.DialContext(ctx, "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("tail dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	limitedConn, ok := conn.(*bwlimit.Conn)
	if !ok || limitedConn.Limiter != limiter {
		t.Fatalf("tail connection has type %T, want configured limiter", conn)
	}
}
