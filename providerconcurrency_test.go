package certstream

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"filippo.io/torchwood"
	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/mod/sumdb/tlog"
)

func TestProviderConcurrency(t *testing.T) {
	for _, tt := range []struct {
		name   string
		limits map[string]int
		want   int
	}{
		{name: "nil map", want: 2},
		{name: "missing provider", limits: map[string]int{"other.com": 5}, want: 2},
		{name: "positive override", limits: map[string]int{"google.com": 5}, want: 5},
		{name: "zero override", limits: map[string]int{"google.com": 0}, want: 2},
		{name: "negative override", limits: map[string]int{"google.com": -1}, want: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lo := &LogOperator{
				CertStream: &CertStream{Config: Config{Concurrency: 2, ProviderConcurrency: tt.limits}},
				Domain:     "google.com",
			}
			if got := lo.concurrency(); got != tt.want {
				t.Fatalf("concurrency = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestStartCopiesProviderConcurrency(t *testing.T) {
	cfg := NewConfig()
	cfg.DataDir = ""
	cfg.HeadDialer = noDialer{}
	cfg.ProviderConcurrency = map[string]int{"google.com": 4}
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	cs, err := Start(ctx, &wg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ProviderConcurrency["google.com"] = 8
	if got := cs.ProviderConcurrency["google.com"]; got != 4 {
		t.Fatalf("stream provider concurrency = %d, want 4", got)
	}
}

type blockedProviderClient struct {
	started chan int64
}

func (c blockedProviderClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	select {
	case c.started <- start:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestProviderConcurrencyClassicWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	starts := make(chan int64, 3)
	lo := &LogOperator{
		CertStream: &CertStream{Config: Config{Concurrency: 1, ProviderConcurrency: map[string]int{"google.com": 3}}},
		Domain:     "google.com",
	}
	ls := &LogStream{LogOperator: lo}
	done := make(chan error, 1)
	go func() {
		_, _, err := ls.getRawEntriesParallel(ctx, blockedProviderClient{started: starts}, 0, 3*LogBatchSize-1, false, nil, nil)
		done <- err
	}()
	var got []int64
	for range 3 {
		select {
		case start := <-starts:
			got = append(got, start)
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d classic requests started, want 3", len(got))
		}
	}
	slices.Sort(got)
	if want := []int64{0, LogBatchSize, 2 * LogBatchSize}; !slices.Equal(got, want) {
		t.Fatalf("classic request starts = %v, want %v", got, want)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("scan after cancellation = %v, want context cancellation", err)
	}
}

type blockedProviderTransport struct {
	started chan struct{}
}

func (tr blockedProviderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case tr.started <- struct{}{}:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestProviderConcurrencyTiledRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	starts := make(chan struct{}, 3)
	lo := &LogOperator{
		CertStream: &CertStream{
			Config:     Config{Concurrency: 1, ProviderConcurrency: map[string]int{"example.com": 3}},
			HeadClient: &http.Client{Transport: blockedProviderTransport{started: starts}},
		},
		Domain: "example.com",
	}
	ls, err := lo.makeTiledStream(newTestTiledLog(t))
	if err != nil {
		t.Fatal(err)
	}
	tiles := []tlog.Tile{
		{H: torchwood.TileHeight, L: 0, N: 0, W: 256},
		{H: torchwood.TileHeight, L: 0, N: 1, W: 256},
		{H: torchwood.TileHeight, L: 0, N: 2, W: 256},
	}
	done := make(chan error, 1)
	go func() {
		_, err := ls.headTile.TileReader().ReadTiles(ctx, tiles)
		done <- err
	}()
	for i := range 3 {
		select {
		case <-starts:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d tiled requests started, want 3", i)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("tile scan after cancellation = %v, want context cancellation", err)
	}
}
