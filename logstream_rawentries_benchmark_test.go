package certstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
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

type providerBenchmarkTransport struct {
	payload []byte
	delay   time.Duration
}

func (tr providerBenchmarkTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if tr.delay > 0 {
		time.Sleep(tr.delay)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(tr.payload)),
	}, nil
}

// BenchmarkProviderConcurrencyClassic measures provider limits on classic reads.
//
// It uses 32-entry responses with 10 ms per-request latency.
func BenchmarkProviderConcurrencyClassic(b *testing.B) {
	entry := makeTestLeafEntry(b, time.Now().UTC().Truncate(time.Millisecond))
	entries := make([]ct.LeafEntry, 32)
	for i := range entries {
		entries[i] = entry
	}
	payload, err := json.Marshal(ct.GetEntriesResponse{Entries: entries})
	if err != nil {
		b.Fatal(err)
	}
	base := &http.Client{Transport: providerBenchmarkTransport{payload: payload, delay: 10 * time.Millisecond}}
	for _, tc := range []struct {
		name      string
		overrides map[string]int
	}{
		{name: "base2"},
		{name: "google4", overrides: map[string]int{"googleapis.com": 4}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cs := &CertStream{Config: Config{Concurrency: 2, ProviderConcurrency: tc.overrides}, HeadClient: base}
			lo := &LogOperator{CertStream: cs, Domain: OperatorDomain("https://ct.googleapis.com/logs/us1/")}
			handle := func(context.Context, time.Time, *LogEntry) bool { return false }
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				ls, err := lo.makeStream(&loglist3.Log{URL: "https://ct.googleapis.com/logs/us1/"})
				if err != nil {
					b.Fatal(err)
				}
				for pb.Next() {
					_, next, err := ls.getRawEntriesParallel(b.Context(), ls.headClient, 0, 1023, false, handle, nil)
					if err != nil || next != 1024 {
						b.Fatalf("getRawEntriesParallel next=%d, err=%v", next, err)
					}
				}
			})
		})
	}
}

// BenchmarkProviderConcurrencyShortScan measures worker setup for one entry.
//
// It runs the classic HTTP and parsing path without synthetic network latency.
func BenchmarkProviderConcurrencyShortScan(b *testing.B) {
	entry := makeTestLeafEntry(b, time.Now().UTC().Truncate(time.Millisecond))
	payload, err := json.Marshal(ct.GetEntriesResponse{Entries: []ct.LeafEntry{entry}})
	if err != nil {
		b.Fatal(err)
	}
	base := &http.Client{Transport: providerBenchmarkTransport{payload: payload}}
	cs := &CertStream{Config: Config{Concurrency: 2}, HeadClient: base}
	lo := &LogOperator{CertStream: cs, Domain: "googleapis.com"}
	handle := func(context.Context, time.Time, *LogEntry) bool { return false }
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ls, err := lo.makeStream(&loglist3.Log{URL: "https://ct.googleapis.com/logs/us1/"})
		if err != nil {
			b.Fatal(err)
		}
		for pb.Next() {
			_, next, err := ls.getRawEntriesParallel(b.Context(), ls.headClient, 0, 0, false, handle, nil)
			if err != nil || next != 1 {
				b.Fatalf("getRawEntriesParallel next=%d, err=%v", next, err)
			}
		}
	})
}
