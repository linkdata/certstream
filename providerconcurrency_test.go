package certstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/torchwood"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
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
			cs := &CertStream{Config: Config{Concurrency: 2, ProviderConcurrency: tt.limits}}
			if got := cs.CurrentProviderConcurrency("google.com"); got != tt.want {
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

func TestSetProviderConcurrencyForCurrentAndFutureOperators(t *testing.T) {
	cs := &CertStream{
		Config:    Config{Concurrency: 2, ProviderConcurrency: map[string]int{"googleapis.com": 4}},
		operators: make(map[string]*LogOperator),
	}
	if got := cs.CurrentProviderConcurrency("googleapis.com"); got != 4 {
		t.Fatalf("initial concurrency = %d, want 4", got)
	}
	cs.SetProviderConcurrency("googleapis.com", 0)
	if got := cs.CurrentProviderConcurrency("googleapis.com"); got != 2 {
		t.Fatalf("reset concurrency = %d, want 2", got)
	}
	cs.lifecycleMu.Lock()
	lo, err := cs.ensureOperator(t.Context(), &loglist3.Operator{Name: "Google"}, "googleapis.com")
	cs.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := lo.limit; got != 2 {
		t.Fatalf("new operator concurrency = %d, want 2", got)
	}
	cs.SetProviderConcurrency("googleapis.com", 6)
	if got := lo.limit; got != 6 {
		t.Fatalf("active operator concurrency = %d, want 6", got)
	}
	cs.SetProviderConcurrency("other.com", 3)
	cs.lifecycleMu.Lock()
	other, err := cs.ensureOperator(t.Context(), &loglist3.Operator{Name: "Other"}, "other.com")
	cs.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := other.limit; got != 3 {
		t.Fatalf("future operator concurrency = %d, want 3", got)
	}
	if got := cs.ProviderConcurrency["googleapis.com"]; got != 4 {
		t.Fatalf("startup config changed to %d, want 4", got)
	}
}

func TestSetProviderConcurrencyDuringOperatorRegistration(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	cs.Concurrency = 2
	cs.DataDir = ""
	cs.HeadClient = &http.Client{Transport: blockedReaderTransport{}}
	base, err := loglist3.NewFromJSON([]byte(sampleLogData))
	if err != nil {
		t.Fatal(err)
	}
	log := *base.Operators[0].Logs[1]
	log.URL = "https://logs.example.com/live/"
	domain := OperatorDomain(log.URL)
	op := &loglist3.Operator{Name: "Provider", Email: []string{"provider@example.com"}}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	var streamWG sync.WaitGroup
	defer func() {
		cancel()
		streamWG.Wait()
	}()
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, db.Pfx(`LOCK TABLE CERTDB_operator IN ACCESS EXCLUSIVE MODE`)); err != nil {
		t.Fatal(err)
	}
	registered := make(chan error, 1)
	go func() { registered <- cs.ensureOperatorAndLog(runCtx, op, &log, &streamWG) }()
	deadline := time.Now().Add(5 * time.Second)
	for db.Stat().AcquiredConns() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if db.Stat().AcquiredConns() < 2 {
		t.Fatal("operator registration did not reach blocked database setup")
	}
	updated := make(chan struct{})
	go func() {
		cs.SetProviderConcurrency(domain, 4)
		close(updated)
	}()
	select {
	case <-updated:
	case <-time.After(time.Second):
		t.Fatal("provider update blocked behind operator database setup")
	}
	if got := cs.CurrentProviderConcurrency(domain); got != 4 {
		t.Fatalf("configured limit during registration = %d, want 4", got)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-registered; err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	lo := cs.operators[domain]
	cs.mu.Unlock()
	if lo == nil || lo.limit != 4 {
		t.Fatalf("new operator = %v; want limit 4", lo)
	}
}

func waitProviderLimitBlocked(t *testing.T, lo *LogOperator) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		lo.limitMu.Lock()
		blocked := lo.limitWait != nil
		lo.limitMu.Unlock()
		if blocked {
			return
		}
		select {
		case <-tick.C:
		case <-timeout.C:
			t.Fatal("provider request did not wait for a permit")
		}
	}
}

type gatedProviderBody struct {
	ctx  context.Context
	gate <-chan struct{}
	*bytes.Reader
}

func (body *gatedProviderBody) Read(p []byte) (int, error) {
	select {
	case <-body.gate:
		return body.Reader.Read(p)
	case <-body.ctx.Done():
		return 0, body.ctx.Err()
	}
}

func (body *gatedProviderBody) Close() error { return nil }

func TestProviderConcurrencyClassicLiveUpdate(t *testing.T) {
	entry := makeTestLeafEntry(t, time.Now().UTC().Truncate(time.Millisecond))
	entries := make([]ct.LeafEntry, 32)
	for i := range entries {
		entries[i] = entry
	}
	payload, err := json.Marshal(ct.GetEntriesResponse{Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate := make(chan struct{})
	gateClosed := false
	defer func() {
		if !gateClosed {
			close(gate)
		}
	}()
	starts := make(chan struct{}, 4)
	base := &http.Client{Transport: retryAfterRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		select {
		case starts <- struct{}{}:
		default:
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &gatedProviderBody{ctx: req.Context(), gate: gate, Reader: bytes.NewReader(payload)},
		}, nil
	})}
	cs := &CertStream{Config: Config{Concurrency: 2}, HeadClient: base, operators: make(map[string]*LogOperator)}
	lo := &LogOperator{
		CertStream: cs,
		Domain:     "googleapis.com",
	}
	cs.operators[lo.Domain] = lo
	ls, err := lo.makeStream(&loglist3.Log{URL: "https://ct.googleapis.com/logs/us1/"})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		next int64
		err  error
	}
	done := make(chan result, 1)
	go func() {
		_, next, err := ls.getRawEntriesParallel(ctx, ls.headClient, 0, 4*LogBatchSize-1, false,
			func(context.Context, time.Time, *LogEntry) bool { return false }, nil)
		done <- result{next: next, err: err}
	}()
	for i := range 2 {
		select {
		case <-starts:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d classic requests started, want 2", i)
		}
	}
	select {
	case <-starts:
		t.Fatal("more than 2 classic requests started before update")
	default:
	}
	cs.SetProviderConcurrency(lo.Domain, 4)
	for i := range 2 {
		select {
		case <-starts:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d additional classic requests started after update, want 2", i)
		}
	}
	close(gate)
	gateClosed = true
	select {
	case got := <-done:
		if got.err != nil || got.next != 4*LogBatchSize {
			t.Fatalf("classic scan = (%d, %v), want (%d, nil)", got.next, got.err, 4*LogBatchSize)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("classic scan did not finish")
	}
}

func TestProviderConcurrencyDecreaseAndCancellation(t *testing.T) {
	cs := &CertStream{Config: Config{Concurrency: 4}, operators: make(map[string]*LogOperator)}
	lo := &LogOperator{CertStream: cs, Domain: "example.com"}
	cs.operators[lo.Domain] = lo
	var calls atomic.Int64
	base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})}
	client := newLimitedProviderClient(base, lo, nil)
	const url = "https://log.example.com/ct/v1/get-entries"
	var held []*http.Response
	for range 4 {
		resp, err := retryAfterDo(t.Context(), client, url)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, resp)
	}
	cs.SetProviderConcurrency(lo.Domain, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := retryAfterDo(ctx, client, url)
		done <- result{resp: resp, err: err}
	}()
	waitProviderLimitBlocked(t, lo)
	for _, resp := range held[:3] {
		closeRetryAfterResponse(t, resp)
		waitProviderLimitBlocked(t, lo)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("requests started while active count exceeds new limit = %d, want 4", got)
	}
	closeRetryAfterResponse(t, held[3])
	var fifth result
	select {
	case fifth = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not start after active count fell below limit")
	}
	if fifth.err != nil || fifth.resp == nil || calls.Load() != 5 {
		t.Fatalf("fifth request = (%v, %v), total calls = %d", fifth.resp, fifth.err, calls.Load())
	}
	cancelCtx, cancelQueued := context.WithCancel(t.Context())
	queued := make(chan error, 1)
	go func() {
		resp, err := retryAfterDo(cancelCtx, client, url)
		if resp != nil {
			err = errors.Join(err, resp.Body.Close())
		}
		queued <- err
	}()
	waitProviderLimitBlocked(t, lo)
	cancelQueued()
	if err := <-queued; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued request after cancellation = %v, want context cancellation", err)
	}
	if got := calls.Load(); got != 5 {
		t.Fatalf("canceled request reached transport; total calls = %d, want 5", got)
	}
	closeRetryAfterResponse(t, fifth.resp)
}

func TestProviderConcurrencyPermitRechecksCooldown(t *testing.T) {
	cs := &CertStream{Config: Config{Concurrency: 1}}
	lo := &LogOperator{CertStream: cs}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int64
	base := &http.Client{Transport: retryAfterRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			select {
			case <-releaseFirst:
				return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		return retryAfterResponse(http.StatusOK, ""), nil
	})}
	client := newLimitedProviderClient(base, lo, nil)
	const url = "https://log.example.com/ct/v1/get-entries"
	type result struct {
		resp *http.Response
		err  error
	}
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	defer cancelFirst()
	firstDone := make(chan result, 1)
	go func() {
		resp, err := retryAfterDo(firstCtx, client, url)
		firstDone <- result{resp: resp, err: err}
	}()
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not start")
	}
	secondCtx, cancelSecond := context.WithCancel(t.Context())
	defer cancelSecond()
	secondDone := make(chan result, 1)
	go func() {
		resp, err := retryAfterDo(secondCtx, client, url)
		secondDone <- result{resp: resp, err: err}
	}()
	waitProviderLimitBlocked(t, lo)
	close(releaseFirst)
	first := <-firstDone
	if first.err != nil || first.resp == nil || first.resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first response = (%v, %v), want 429", first.resp, first.err)
	}
	closeRetryAfterResponse(t, first.resp)
	select {
	case second := <-secondDone:
		if second.resp != nil {
			closeRetryAfterResponse(t, second.resp)
		}
		t.Fatalf("queued request bypassed Retry-After: %v", second.err)
	case <-time.After(100 * time.Millisecond):
	}
	cancelSecond()
	second := <-secondDone
	if !errors.Is(second.err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("queued request = %v, network calls = %d; want canceled and one call", second.err, calls.Load())
	}
}

func TestProviderConcurrencyTailGapLimitsAndCooldown(t *testing.T) {
	lo := &LogOperator{CertStream: &CertStream{Config: Config{Concurrency: 2}}}
	var calls atomic.Int64
	base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return retryAfterResponse(http.StatusOK, ""), nil
	})}
	tail := newLimitedProviderClient(base, lo, nil)
	gap := newLimitedProviderClient(base, lo, tail.Transport.(*retryAfterTransport))
	const url = "https://log.example.com/tile/data/1"
	first, err := retryAfterDo(t.Context(), tail, url)
	if err != nil {
		t.Fatal(err)
	}
	second, err := retryAfterDo(t.Context(), tail, url)
	if err != nil {
		t.Fatal(err)
	}
	third, err := retryAfterDo(t.Context(), gap, url)
	if err != nil {
		t.Fatalf("gap request shares the tail's permit count: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("tail and gap network calls = %d, want 3", got)
	}
	closeRetryAfterResponse(t, first)
	closeRetryAfterResponse(t, second)
	closeRetryAfterResponse(t, third)

	cooldownBase := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
	})}
	tail = newLimitedProviderClient(cooldownBase, lo, nil)
	gap = newLimitedProviderClient(cooldownBase, lo, tail.Transport.(*retryAfterTransport))
	resp, err := retryAfterDo(t.Context(), tail, url)
	if err != nil {
		t.Fatal(err)
	}
	closeRetryAfterResponse(t, resp)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err = retryAfterDo(ctx, gap, url); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("gap request during shared cooldown = %v, want deadline", err)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("gap request bypassed shared cooldown; network calls = %d, want 4", got)
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
	starts := make(chan struct{}, 4)
	cs := &CertStream{
		Config:     Config{Concurrency: 2},
		HeadClient: &http.Client{Transport: blockedProviderTransport{started: starts}},
		operators:  make(map[string]*LogOperator),
	}
	lo := &LogOperator{
		CertStream: cs,
		Domain:     "example.com",
	}
	cs.operators[lo.Domain] = lo
	ls, err := lo.makeTiledStream(newTestTiledLog(t))
	if err != nil {
		t.Fatal(err)
	}
	tiles := []tlog.Tile{
		{H: torchwood.TileHeight, L: 0, N: 0, W: 256},
		{H: torchwood.TileHeight, L: 0, N: 1, W: 256},
		{H: torchwood.TileHeight, L: 0, N: 2, W: 256},
		{H: torchwood.TileHeight, L: 0, N: 3, W: 256},
	}
	done := make(chan error, 1)
	go func() {
		_, err := ls.headTile.TileReader().ReadTiles(ctx, tiles)
		done <- err
	}()
	for i := range 2 {
		select {
		case <-starts:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d tiled requests started, want 2", i)
		}
	}
	waitProviderLimitBlocked(t, lo)
	select {
	case <-starts:
		t.Fatal("more than 2 tiled requests started before update")
	default:
	}
	cs.SetProviderConcurrency(lo.Domain, 4)
	for i := range 2 {
		select {
		case <-starts:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d additional tiled requests started after update, want 2", i)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("tile scan after cancellation = %v, want context cancellation", err)
	}
}
