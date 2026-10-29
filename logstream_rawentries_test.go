package certstream

import (
	"context"
	"errors"
	"io"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

func TestGetRawEntriesParallelStopsBeforeSchedulingOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client := &controlledRawEntriesClient{}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: &CertStream{Config: Config{Concurrency: 4}}}}
	_, next, err := ls.getRawEntriesParallel(ctx, client, 0, math.MaxInt64, false, nil, nil)
	if !errors.Is(err, context.Canceled) || next != 0 {
		t.Fatalf("canceled scan = (next %d, err %v)", next, err)
	}
	if got := client.Calls(); len(got) != 0 {
		t.Fatalf("scheduled canceled ranges: %v", got)
	}
}

type rawEntriesCall struct {
	start int64
	end   int64
}

type stubRawEntriesClient struct {
	entry ct.LeafEntry
	err   error
	calls []rawEntriesCall
}

func (c *stubRawEntriesClient) GetRawEntries(ctx context.Context, start, end int64) (resp *ct.GetEntriesResponse, err error) {
	c.calls = append(c.calls, rawEntriesCall{start: start, end: end})
	if c.err == nil {
		count := int(end-start) + 1
		entries := make([]ct.LeafEntry, count)
		for i := range entries {
			entries[i] = c.entry
		}
		resp = &ct.GetEntriesResponse{Entries: entries}
	} else {
		err = c.err
	}
	return
}

type controlledRawEntriesClient struct {
	entry ct.LeafEntry
	mu    sync.Mutex
	calls []rawEntriesCall
	waits map[int64]chan struct{}
	done  map[int64]chan struct{}
	errs  map[int64]error
}

func (c *controlledRawEntriesClient) Calls() []rawEntriesCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func (c *controlledRawEntriesClient) GetRawEntries(ctx context.Context, start, end int64) (resp *ct.GetEntriesResponse, err error) {
	c.mu.Lock()
	c.calls = append(c.calls, rawEntriesCall{start: start, end: end})
	waitCh := c.waits[start]
	doneCh := c.done[start]
	if c.errs != nil {
		err = c.errs[start]
	}
	entry := c.entry
	c.mu.Unlock()

	if waitCh != nil {
		select {
		case <-waitCh:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err == nil {
		count := int(end-start) + 1
		entries := make([]ct.LeafEntry, count)
		for i := range entries {
			entries[i] = entry
		}
		resp = &ct.GetEntriesResponse{Entries: entries}
	}
	if doneCh != nil {
		close(doneCh)
	}
	return
}

func sortedRawEntriesCalls(calls []rawEntriesCall) []rawEntriesCall {
	sorted := slices.Clone(calls)
	slices.SortFunc(sorted, func(a, b rawEntriesCall) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		if a.end < b.end {
			return -1
		}
		if a.end > b.end {
			return 1
		}
		return 0
	})
	return sorted
}

type coercingRawEntriesClient struct {
	entry ct.LeafEntry
	calls []rawEntriesCall
}

func (c *coercingRawEntriesClient) GetRawEntries(_ context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	c.calls = append(c.calls, rawEntriesCall{start: start, end: end})
	count := min(end-start+1, int64(32))
	if start%256 == 0 && end-start == 255 {
		count = 256
	} else if remainder := start % 32; remainder != 0 {
		count = min(count, 32-remainder)
	}
	entries := make([]ct.LeafEntry, int(count))
	for i := range entries {
		entries[i] = c.entry
	}
	return &ct.GetEntriesResponse{Entries: entries}, nil
}

func TestRawEntriesStopIndexAlignsWindows(t *testing.T) {
	if got := LogBatchSize; got != 256 {
		t.Fatalf("default LogBatchSize = %d, want 256", got)
	}
	for _, tc := range []struct {
		start, end, want int64
	}{
		{0, 1023, 255},
		{1025, 2048, 1279},
		{1280, 2048, 1535},
		{2048, 2048, 2048},
	} {
		if got := rawEntriesStopIndex(tc.start, tc.end); got != tc.want {
			t.Errorf("rawEntriesStopIndex(%d, %d) = %d, want %d", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestGetRawEntriesConvergesOn256(t *testing.T) {
	oldBatchSize := LogBatchSize
	LogBatchSize = 256
	t.Cleanup(func() { LogBatchSize = oldBatchSize })

	entry := makeTestLeafEntry(t, time.Now().UTC().Truncate(time.Millisecond))
	client := &coercingRawEntriesClient{entry: entry}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: &CertStream{}}}
	ls.MinIndex.Store(-1)
	ls.MaxIndex.Store(-1)
	const start, end = int64(1025), int64(1791)
	var indexes []int64
	var backfill atomic.Int64
	backfill.Store(end - start + 1)
	handle := func(_ context.Context, _ time.Time, le *LogEntry) bool {
		indexes = append(indexes, le.LogIndex)
		return false
	}
	_, next, err := ls.getRawEntries(t.Context(), client, start, end, true, handle, &backfill)
	if err != nil || next != end+1 {
		t.Fatalf("getRawEntries next=%d, err=%v", next, err)
	}
	if got := backfill.Load(); got != 0 {
		t.Errorf("Backfill = %d, want 0", got)
	}
	if got, want := len(indexes), int(end-start+1); got != want {
		t.Fatalf("handled %d entries, want %d", got, want)
	}
	for i, got := range indexes {
		if want := start + int64(i); got != want {
			t.Fatalf("entry %d has index %d, want %d", i, got, want)
		}
	}
	if got, want := client.calls, []rawEntriesCall{
		{1025, 1279}, {1056, 1279}, {1088, 1279}, {1120, 1279},
		{1152, 1279}, {1184, 1279}, {1216, 1279}, {1248, 1279},
		{1280, 1535}, {1536, 1791},
	}; !slices.Equal(got, want) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}

func TestGetRawEntriesParallelUsesAlignedWindows(t *testing.T) {
	oldBatchSize := LogBatchSize
	LogBatchSize = 256
	t.Cleanup(func() { LogBatchSize = oldBatchSize })

	entry := makeTestLeafEntry(t, time.Now().UTC().Truncate(time.Millisecond))
	client := &controlledRawEntriesClient{entry: entry}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: &CertStream{Config: Config{Concurrency: 3}}}}
	const start, end = int64(1025), int64(1791)
	var indexes []int64
	var mu sync.Mutex
	handle := func(_ context.Context, _ time.Time, le *LogEntry) bool {
		mu.Lock()
		indexes = append(indexes, le.LogIndex)
		mu.Unlock()
		return false
	}
	_, next, err := ls.getRawEntriesParallel(t.Context(), client, start, end, false, handle, nil)
	if err != nil || next != end+1 {
		t.Fatalf("getRawEntriesParallel next=%d, err=%v", next, err)
	}
	if got, want := sortedRawEntriesCalls(client.Calls()), []rawEntriesCall{
		{1025, 1279}, {1280, 1535}, {1536, 1791},
	}; !slices.Equal(got, want) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	mu.Lock()
	slices.Sort(indexes)
	mu.Unlock()
	if got, want := len(indexes), int(end-start+1); got != want {
		t.Fatalf("handled %d entries, want %d", got, want)
	}
	for i, got := range indexes {
		if want := start + int64(i); got != want {
			t.Fatalf("entry %d has index %d, want %d", i, got, want)
		}
	}
}

func makeTestLeafEntry(t testing.TB, now time.Time) (leaf ct.LeafEntry) {
	t.Helper()
	der := makeTestCertificate(t, now)
	var err error
	var cert *ctx509.Certificate
	if cert, err = ctx509.ParseCertificate(der); err == nil {
		var merkleLeaf *ct.MerkleTreeLeaf
		if merkleLeaf, err = ct.MerkleTreeLeafFromChain([]*ctx509.Certificate{cert}, ct.X509LogEntryType, uint64(now.UnixMilli())); err == nil {
			var leafInput []byte
			if leafInput, err = tls.Marshal(*merkleLeaf); err == nil {
				var extra []byte
				if extra, err = tls.Marshal(ct.CertificateChain{}); err == nil {
					leaf = ct.LeafEntry{
						LeafInput: leafInput,
						ExtraData: extra,
					}
				}
			}
		}
	}
	if err != nil {
		t.Fatalf("makeTestLeafEntry: %v", err)
	}
	return
}

func TestGetRawEntriesProcessesEntries(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	entry := makeTestLeafEntry(t, now)
	client := &stubRawEntriesClient{entry: entry}

	oldBatchSize := LogBatchSize
	LogBatchSize = 2
	t.Cleanup(func() {
		LogBatchSize = oldBatchSize
	})

	ls := &LogStream{}
	ls.MinIndex.Store(-1)
	ls.MaxIndex.Store(-1)

	var gotIndexes []int64
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		gotIndexes = append(gotIndexes, le.LogIndex)
		if le.LogIndex == 2 {
			wanted = true
		}
		return
	}

	var gapcounter atomic.Int64
	gapcounter.Store(5)

	var wanted bool
	var next int64
	var err error
	if wanted, next, err = ls.getRawEntries(ctx, client, 0, 4, false, handleFn, &gapcounter); err == nil {
		if !wanted {
			t.Fatalf("wanted = false, want true")
		}
		if got := next; got != 5 {
			t.Fatalf("next = %d, want 5", got)
		}
		if got := gapcounter.Load(); got != 0 {
			t.Fatalf("gapcounter = %d, want 0", got)
		}
		if got, want := ls.MinIndex.Load(), int64(0); got != want {
			t.Fatalf("MinIndex = %d, want %d", got, want)
		}
		if got, want := ls.MaxIndex.Load(), int64(4); got != want {
			t.Fatalf("MaxIndex = %d, want %d", got, want)
		}
		if got, want := gotIndexes, []int64{0, 1, 2, 3, 4}; !slices.Equal(got, want) {
			t.Fatalf("indexes = %v, want %v", got, want)
		}
		if got, want := client.calls, []rawEntriesCall{{start: 0, end: 1}, {start: 2, end: 3}, {start: 4, end: 4}}; !slices.Equal(got, want) {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	} else {
		t.Fatalf("getRawEntries error: %v", err)
	}
}

func TestGetRawEntriesStopsOnFatalError(t *testing.T) {
	ctx := t.Context()
	client := &stubRawEntriesClient{err: io.ErrNoProgress}
	ls := &LogStream{
		LogOperator: &LogOperator{
			CertStream: &CertStream{},
		},
	}
	ls.MinIndex.Store(-1)
	ls.MaxIndex.Store(-1)

	var handled int
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		handled++
		return
	}

	var gapcounter atomic.Int64
	gapcounter.Store(3)

	var wanted bool
	var next int64
	var err error
	if wanted, next, err = ls.getRawEntries(ctx, client, 10, 12, false, handleFn, &gapcounter); err != nil {
		if wanted {
			t.Fatalf("wanted = true, want false")
		}
		if got := next; got != 10 {
			t.Fatalf("next = %d, want 10", got)
		}
		if handled != 0 {
			t.Fatalf("handled = %d, want 0", handled)
		}
		if got := gapcounter.Load(); got != 0 {
			t.Fatalf("gapcounter = %d, want 0", got)
		}
		if !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("error = %v, want %v", err, io.ErrNoProgress)
		}
		if got, want := client.calls, []rawEntriesCall{{start: 10, end: 12}}; !slices.Equal(got, want) {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	} else {
		t.Fatalf("getRawEntries error: nil, want non-nil")
	}
}

func TestGetRawEntriesParallelProcessesEntries(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	entry := makeTestLeafEntry(t, now)
	client := &controlledRawEntriesClient{entry: entry}

	oldBatchSize := LogBatchSize
	LogBatchSize = 2
	t.Cleanup(func() {
		LogBatchSize = oldBatchSize
	})

	ls := &LogStream{
		LogOperator: &LogOperator{
			CertStream: &CertStream{
				Config: Config{
					Concurrency: 3,
				},
			},
		},
	}
	ls.MinIndex.Store(-1)
	ls.MaxIndex.Store(-1)

	var gotMu sync.Mutex
	var gotIndexes []int64
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		gotMu.Lock()
		gotIndexes = append(gotIndexes, le.LogIndex)
		gotMu.Unlock()
		if le.LogIndex == 4 {
			wanted = true
		}
		return
	}

	var gapcounter atomic.Int64
	gapcounter.Store(6)

	var next int64
	var wanted bool
	wanted, next, _ = ls.getRawEntriesParallel(ctx, client, 0, 5, false, handleFn, &gapcounter)
	if !wanted {
		t.Fatalf("wanted = false, want true")
	}
	if got := gapcounter.Load(); got != 0 {
		t.Fatalf("gapcounter = %d, want 0", got)
	}
	if got, want := next, int64(6); got != want {
		t.Fatalf("next = %d, want %d", got, want)
	}
	if got, want := ls.MinIndex.Load(), int64(0); got != want {
		t.Fatalf("MinIndex = %d, want %d", got, want)
	}
	if got, want := ls.MaxIndex.Load(), int64(5); got != want {
		t.Fatalf("MaxIndex = %d, want %d", got, want)
	}

	gotMu.Lock()
	sortedIndexes := slices.Clone(gotIndexes)
	gotMu.Unlock()
	slices.Sort(sortedIndexes)
	if got, want := sortedIndexes, []int64{0, 1, 2, 3, 4, 5}; !slices.Equal(got, want) {
		t.Fatalf("indexes = %v, want %v", got, want)
	}

	if got, want := sortedRawEntriesCalls(client.Calls()), []rawEntriesCall{{start: 0, end: 1}, {start: 2, end: 3}, {start: 4, end: 5}}; !slices.Equal(got, want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
}

func TestGetRawEntriesParallelAdvancesNextOutOfOrder(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	entry := makeTestLeafEntry(t, now)

	waitStart := make(chan struct{})
	doneLast := make(chan struct{})
	client := &controlledRawEntriesClient{
		entry: entry,
		waits: map[int64]chan struct{}{
			0: waitStart,
		},
		done: map[int64]chan struct{}{
			4: doneLast,
		},
	}

	oldBatchSize := LogBatchSize
	LogBatchSize = 2
	t.Cleanup(func() {
		LogBatchSize = oldBatchSize
	})

	ls := &LogStream{
		LogOperator: &LogOperator{
			CertStream: &CertStream{
				Config: Config{
					Concurrency: 2,
				},
			},
		},
	}
	ls.MinIndex.Store(-1)
	ls.MaxIndex.Store(-1)

	var gotMu sync.Mutex
	var gotIndexes []int64
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		gotMu.Lock()
		gotIndexes = append(gotIndexes, le.LogIndex)
		gotMu.Unlock()
		return
	}

	type result struct {
		next   int64
		wanted bool
	}
	resultCh := make(chan result, 1)
	go func() {
		wanted, next, err := ls.getRawEntriesParallel(ctx, client, 0, 5, false, handleFn, nil)
		resultCh <- result{next: next, wanted: wanted}
		if err != nil {
			t.Error(err)
		}
	}()

	select {
	case <-doneLast:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for last range")
	}
	close(waitStart)

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for result")
	}

	if res.wanted {
		t.Fatalf("wanted = true, want false")
	}
	if got, want := res.next, int64(6); got != want {
		t.Fatalf("next = %d, want %d", got, want)
	}

	gotMu.Lock()
	sortedIndexes := slices.Clone(gotIndexes)
	gotMu.Unlock()
	slices.Sort(sortedIndexes)
	if got, want := sortedIndexes, []int64{0, 1, 2, 3, 4, 5}; !slices.Equal(got, want) {
		t.Fatalf("indexes = %v, want %v", got, want)
	}
}
