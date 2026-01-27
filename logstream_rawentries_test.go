package certstream

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

type fakeRawEntriesClient struct {
	errAtStart int64
	limit      int
}

func (f *fakeRawEntriesClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if start >= f.errAtStart {
		return nil, os.ErrInvalid
	}
	count := f.limit
	remaining := int(end - start + 1)
	if remaining < count {
		count = remaining
	}
	entries := make([]ct.LeafEntry, count)
	for i := 0; i < count; i++ {
		entries[i] = ct.LeafEntry{LeafInput: []byte("invalid"), ExtraData: []byte("invalid")}
	}
	return &ct.GetEntriesResponse{Entries: entries}, nil
}

type emptyRawEntriesClient struct{}

func (e *emptyRawEntriesClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &ct.GetEntriesResponse{}, nil
}

type rawEntriesCall struct {
	start int64
	end   int64
}

type recordingRawEntriesClient struct {
	mu    sync.Mutex
	calls []rawEntriesCall
	limit int
}

func (r *recordingRawEntriesClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	r.mu.Lock()
	r.calls = append(r.calls, rawEntriesCall{start: start, end: end})
	r.mu.Unlock()
	count := r.limit
	remaining := int(end - start + 1)
	if remaining < count {
		count = remaining
	}
	entries := make([]ct.LeafEntry, count)
	for i := 0; i < count; i++ {
		entries[i] = ct.LeafEntry{LeafInput: []byte("invalid"), ExtraData: []byte("invalid")}
	}
	return &ct.GetEntriesResponse{Entries: entries}, nil
}

func (r *recordingRawEntriesClient) Calls() []rawEntriesCall {
	r.mu.Lock()
	calls := make([]rawEntriesCall, len(r.calls))
	copy(calls, r.calls)
	r.mu.Unlock()
	return calls
}

type phaseBlockingRawEntriesClient struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
	limit   int
}

func (b *phaseBlockingRawEntriesClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	b.mu.Lock()
	b.calls++
	call := b.calls
	b.mu.Unlock()
	if call > 1 {
		select {
		case b.started <- struct{}{}:
		default:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-b.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	count := b.limit
	remaining := int(end - start + 1)
	if remaining < count {
		count = remaining
	}
	entries := make([]ct.LeafEntry, count)
	for i := 0; i < count; i++ {
		entries[i] = ct.LeafEntry{LeafInput: []byte("invalid"), ExtraData: []byte("invalid")}
	}
	return &ct.GetEntriesResponse{Entries: entries}, nil
}

func newTestLogStream() *LogStream {
	cs := &CertStream{}
	lo := &LogOperator{CertStream: cs}
	ls := &LogStream{LogOperator: lo}
	return ls
}

func TestGetRawEntriesSubRangeChunksInOrder(t *testing.T) {
	ls := newTestLogStream()
	client := &recordingRawEntriesClient{limit: 10}
	originalBatch := LogBatchSize
	LogBatchSize = 2
	defer func() {
		LogBatchSize = originalBatch
	}()
	entries, err := ls.getRawEntriesSubRange(t.Context(), client, 0, 4, false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(entries) != 5 {
		t.Fatalf("entries = %d, want 5", len(entries))
	}
	calls := client.Calls()
	if len(calls) != 3 {
		t.Fatalf("calls = %d, want 3", len(calls))
	}
	if calls[0].start != 0 || calls[0].end != 1 {
		t.Fatalf("calls[0] = %d..%d, want 0..1", calls[0].start, calls[0].end)
	}
	if calls[1].start != 2 || calls[1].end != 3 {
		t.Fatalf("calls[1] = %d..%d, want 2..3", calls[1].start, calls[1].end)
	}
	if calls[2].start != 4 || calls[2].end != 4 {
		t.Fatalf("calls[2] = %d..%d, want 4..4", calls[2].start, calls[2].end)
	}
}

func TestGetRawEntriesSubRangeNoProgress(t *testing.T) {
	ls := newTestLogStream()
	client := &emptyRawEntriesClient{}
	entries, err := ls.getRawEntriesSubRange(t.Context(), client, 0, 1, false)
	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("err = %v, want %v", err, io.ErrNoProgress)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(entries))
	}
}

func TestGetRawEntriesSubRangeReturnsPartialEntriesOnError(t *testing.T) {
	ls := newTestLogStream()
	client := &fakeRawEntriesClient{errAtStart: 2, limit: 1}
	entries, err := ls.getRawEntriesSubRange(t.Context(), client, 0, 3, false)
	if !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("err = %v, want %v", err, os.ErrInvalid)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
}

func TestGetRawEntriesSubRangeHandlesShortResponses(t *testing.T) {
	ls := newTestLogStream()
	client := &recordingRawEntriesClient{limit: 1}
	originalBatch := LogBatchSize
	LogBatchSize = 4
	defer func() {
		LogBatchSize = originalBatch
	}()
	entries, err := ls.getRawEntriesSubRange(t.Context(), client, 0, 3, false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %d, want 4", len(entries))
	}
	calls := client.Calls()
	if len(calls) != 4 {
		t.Fatalf("calls = %d, want 4", len(calls))
	}
	if calls[0].start != 0 || calls[0].end != 3 {
		t.Fatalf("calls[0] = %d..%d, want 0..3", calls[0].start, calls[0].end)
	}
	if calls[1].start != 1 || calls[1].end != 3 {
		t.Fatalf("calls[1] = %d..%d, want 1..3", calls[1].start, calls[1].end)
	}
	if calls[2].start != 2 || calls[2].end != 3 {
		t.Fatalf("calls[2] = %d..%d, want 2..3", calls[2].start, calls[2].end)
	}
	if calls[3].start != 3 || calls[3].end != 3 {
		t.Fatalf("calls[3] = %d..%d, want 3..3", calls[3].start, calls[3].end)
	}
}

func TestGetRawEntriesRangeReturnsNextIndex(t *testing.T) {
	ls := newTestLogStream()
	client := &fakeRawEntriesClient{errAtStart: 100, limit: 2}
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		return true
	}
	next, wanted := ls.getRawEntriesRange(t.Context(), client, 10, 12, false, handleFn, nil)
	if !wanted {
		t.Fatalf("wanted = false, want true")
	}
	if next != 13 {
		t.Fatalf("next = %d, want 13", next)
	}
}

func TestGetRawEntriesRangeSplitsRangeWithParallel(t *testing.T) {
	ls := newTestLogStream()
	client := &recordingRawEntriesClient{limit: 1000}
	originalBatch := LogBatchSize
	LogBatchSize = 64
	defer func() {
		LogBatchSize = originalBatch
	}()
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		return true
	}
	next, wanted := ls.getRawEntriesRange(t.Context(), client, 0, 127, false, handleFn, nil)
	if !wanted {
		t.Fatalf("wanted = false, want true")
	}
	if next != 128 {
		t.Fatalf("next = %d, want 128", next)
	}
	calls := client.Calls()
	if len(calls) != 3 {
		t.Fatalf("calls = %d, want 3", len(calls))
	}
	sort.Slice(calls, func(i, j int) bool {
		return calls[i].start < calls[j].start
	})
	if calls[0].start != 0 || calls[0].end != 63 {
		t.Fatalf("calls[0] = %d..%d, want 0..63", calls[0].start, calls[0].end)
	}
	if calls[1].start != 64 || calls[1].end != 95 {
		t.Fatalf("calls[1] = %d..%d, want 64..95", calls[1].start, calls[1].end)
	}
	if calls[2].start != 96 || calls[2].end != 127 {
		t.Fatalf("calls[2] = %d..%d, want 96..127", calls[2].start, calls[2].end)
	}
}

func TestGetRawEntriesRangeFetchesSubRangesInParallel(t *testing.T) {
	ls := newTestLogStream()
	originalBatch := LogBatchSize
	LogBatchSize = 64
	defer func() {
		LogBatchSize = originalBatch
	}()
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	client := &phaseBlockingRawEntriesClient{started: started, release: release, limit: 1000}
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_, _ = ls.getRawEntriesRange(ctx, client, 0, 127, false, handleFn, nil)
		close(done)
	}()
	<-started
	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second request did not start in parallel")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("getRawEntriesRange did not finish")
	}
}
