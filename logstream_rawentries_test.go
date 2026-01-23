package certstream

import (
	"context"
	"errors"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

type fakeRawEntriesClient struct {
	errAtStart int64
	limit      int
}

func (f *fakeRawEntriesClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if start >= f.errAtStart {
		return nil, errors.New("boom")
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

func TestGetRawEntriesRangeReturnsNextIndex(t *testing.T) {
	cs := &CertStream{}
	lo := &LogOperator{CertStream: cs}
	ls := &LogStream{LogOperator: lo}
	client := &fakeRawEntriesClient{errAtStart: 12, limit: 2}
	handleFn := func(ctx context.Context, now time.Time, le *LogEntry) (wanted bool) {
		return true
	}
	next, wanted := ls.getRawEntriesRange(context.Background(), client, 10, 12, false, handleFn, nil)
	if !wanted {
		t.Fatalf("wanted = false, want true")
	}
	if next != 12 {
		t.Fatalf("next = %d, want 12", next)
	}
}
