package certstream

import (
	"context"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

type trustAsiaBenchmarkClient struct {
	calls int
}

func (c *trustAsiaBenchmarkClient) GetRawEntries(_ context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	c.calls++
	count := min(end-start+1, int64(32))
	if start%256 == 0 && end-start == 255 {
		count = 256
	} else if remainder := start % 32; remainder != 0 {
		count = min(count, 32-remainder)
	}
	return &ct.GetEntriesResponse{Entries: make([]ct.LeafEntry, int(count))}, nil
}

func BenchmarkGetTrustAsiaRawEntries(b *testing.B) {
	for _, tc := range []struct {
		name       string
		start, end int64
	}{
		{name: "aligned", start: 1024, end: 2047},
		{name: "unaligned", start: 1025, end: 2048},
	} {
		b.Run(tc.name, func(b *testing.B) {
			ls := &LogStream{LogOperator: &LogOperator{CertStream: &CertStream{}, Domain: "trustasia.com"}}
			client := &trustAsiaBenchmarkClient{}
			handle := func(context.Context, time.Time, *LogEntry) bool { return false }
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_, next, err := ls.getRawEntries(b.Context(), client, tc.start, tc.end, false, handle, nil)
				if err != nil || next != tc.end+1 {
					b.Fatalf("getRawEntries next=%d, err=%v", next, err)
				}
			}
			b.ReportMetric(float64(client.calls)/float64(b.N), "calls/op")
		})
	}
}

type fullRangeBenchmarkClient struct {
	calls int
}

func (c *fullRangeBenchmarkClient) GetRawEntries(_ context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	c.calls++
	return &ct.GetEntriesResponse{Entries: make([]ct.LeafEntry, int(end-start+1))}, nil
}

func BenchmarkGetFullRawEntries(b *testing.B) {
	const start, end = int64(1024), int64(2047)
	ls := &LogStream{}
	client := &fullRangeBenchmarkClient{}
	handle := func(context.Context, time.Time, *LogEntry) bool { return false }
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, next, err := ls.getRawEntries(b.Context(), client, start, end, false, handle, nil)
		if err != nil || next != end+1 {
			b.Fatalf("getRawEntries next=%d, err=%v", next, err)
		}
	}
	b.ReportMetric(float64(client.calls)/float64(b.N), "calls/op")
}
