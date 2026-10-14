package certstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
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

func TestGetRawEntriesPausesAndResumesAtUnprocessedIndex(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := make(chan *LogEntry, 4)
		ls := testQueueStream(queue)
		client := &controlledRawEntriesClient{entry: makeTestLeafEntry(t, time.Now())}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var seen []int64
		handle := func(_ context.Context, _ time.Time, entry *LogEntry) bool {
			seen = append(seen, entry.LogIndex)
			if entry.LogIndex == 0 {
				for range 3 {
					queue <- &LogEntry{}
				}
			}
			return true
		}
		type result struct {
			wanted bool
			next   int64
			err    error
		}
		var remaining atomic.Int64
		remaining.Store(3)
		done := make(chan result, 1)
		go func() {
			wanted, next, err := ls.getRawEntries(ctx, client, 0, 2, true, handle, &remaining)
			done <- result{wanted, next, err}
		}()
		synctest.Wait()
		if got, want := seen, []int64{0}; !slices.Equal(got, want) {
			t.Fatalf("handled indexes before cancellation = %v, want %v", got, want)
		}
		ls.DB().sendToBatcher(t.Context(), &LogEntry{}) // live entry uses reserved space
		if got := len(queue); got != 4 {
			t.Fatalf("queue length after live entry = %d, want 4", got)
		}
		cancel()
		synctest.Wait()
		first := <-done
		if !first.wanted || first.next != 1 || !errors.Is(first.err, context.Canceled) {
			t.Fatalf("canceled result = %+v, want wanted, next 1, context.Canceled", first)
		}
		if got := remaining.Load(); got != 0 {
			t.Fatalf("remaining after cancellation = %d, want 0", got)
		}
		<-queue
		<-queue // 50% queue usage allows replay to resume
		remaining.Store(2)
		wanted, next, err := ls.getRawEntries(t.Context(), client, first.next, 2, true, handle, &remaining)
		if !wanted || next != 3 || err != nil {
			t.Fatalf("resumed result: wanted=%t next=%d error=%v", wanted, next, err)
		}
		if got, want := seen, []int64{0, 1, 2}; !slices.Equal(got, want) {
			t.Fatalf("handled indexes = %v, want %v", got, want)
		}
		if got := remaining.Load(); got != 0 {
			t.Fatalf("remaining after resume = %d, want 0", got)
		}
		if got, want := client.Calls(), []rawEntriesCall{{start: 0, end: 2}, {start: 1, end: 2}}; !slices.Equal(got, want) {
			t.Fatalf("HTTP calls = %v, want %v", got, want)
		}
	})
}

// BenchmarkRawHistoricalHeadAdmission measures how long a live entry waits
// when historical entries and a slow consumer contend for the same DB queue.
func BenchmarkRawHistoricalHeadAdmission(b *testing.B) {
	var totalHeadLatency atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			queue := make(chan *LogEntry, 16)
			for range 7 {
				queue <- &LogEntry{}
			}
			ls := testQueueStream(queue)
			ctx, cancel := context.WithCancel(b.Context())
			producerDone := make(chan struct{})
			ready := make(chan struct{})
			go func() {
				defer close(producerDone)
				client := &stubRawEntriesClient{}
				_, _, _ = ls.getRawEntries(ctx, client, 0, 15, true,
					func(ctx context.Context, _ time.Time, entry *LogEntry) bool {
						ls.DB().sendToBatcher(ctx, entry)
						if entry.LogIndex == 1 {
							close(ready)
						}
						return false
					}, nil)
			}()
			select {
			case <-ready:
			case <-time.After(time.Second):
				cancel()
				<-producerDone
				b.Fatal("historical producer did not reach queue threshold")
			}
			time.Sleep(250 * time.Microsecond)
			headDone := make(chan struct{})
			drainDone := make(chan struct{})
			go func() {
				defer close(drainDone)
				timer := time.NewTimer(time.Millisecond)
				defer timer.Stop()
				select {
				case <-headDone:
					return
				case <-timer.C:
				}
				for {
					select {
					case <-headDone:
						return
					case <-queue:
					}
				}
			}()
			started := time.Now()
			ls.DB().sendToBatcher(ctx, &LogEntry{})
			totalHeadLatency.Add(time.Since(started).Nanoseconds())
			close(headDone)
			<-drainDone
			cancel()
			<-producerDone
		}
	})
	b.ReportMetric(float64(totalHeadLatency.Load())/float64(b.N), "ns/head")
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
