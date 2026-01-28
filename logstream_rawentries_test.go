package certstream

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

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

func makeTestLeafEntry(t *testing.T, now time.Time) (leaf ct.LeafEntry) {
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
	ctx := context.Background()
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
	var err error
	if wanted, err = ls.getRawEntries(ctx, client, 0, 4, false, handleFn, &gapcounter); err == nil {
		if !wanted {
			t.Fatalf("wanted = false, want true")
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
	ctx := context.Background()
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
	var err error
	if wanted, err = ls.getRawEntries(ctx, client, 10, 12, false, handleFn, &gapcounter); err != nil {
		if wanted {
			t.Fatalf("wanted = true, want false")
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
