package certstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type retryAfterRoundTripFunc func(*http.Request) (*http.Response, error)

func (f retryAfterRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func retryAfterResponse(status int, header string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("response")),
	}
	if header != "" {
		resp.Header.Set("Retry-After", header)
	}
	return resp
}

func retryAfterDo(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func closeRetryAfterResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
}

func TestRetryAfterTime(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		value string
		want  time.Time
	}{
		{name: "seconds", value: "60", want: now.Add(time.Minute)},
		{name: "HTTP date", value: now.Add(2 * time.Minute).Format(http.TimeFormat), want: now.Add(2 * time.Minute)},
		{name: "Skylight UTC date", value: now.Add(2 * time.Minute).Format(time.RFC1123), want: now.Add(2 * time.Minute)},
		{name: "empty"},
		{name: "zero", value: "0"},
		{name: "negative", value: "-1"},
		{name: "malformed", value: "later"},
		{name: "overflow", value: "9223372037"},
		{name: "past date", value: now.Add(-time.Minute).Format(http.TimeFormat)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryAfterTime(tt.value, now); !got.Equal(tt.want) {
				t.Fatalf("retryAfterTime(%q) = %v; want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestNewProviderClientUsesDefaultTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	client := newProviderClient(&http.Client{Timeout: time.Second})
	resp, err := retryAfterDo(t.Context(), client, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	closeRetryAfterResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
}

func TestRetryAfterTransportCancelsFailedNetworkRequest(t *testing.T) {
	wantErr := errors.New("dial failed")
	var requestContext context.Context
	base := &http.Client{
		Timeout: time.Second,
		Transport: retryAfterRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestContext = req.Context()
			return nil, wantErr
		}),
	}
	_, err := retryAfterDo(t.Context(), newProviderClient(base), "https://log.example/ct/v1/get-sth")
	if !errors.Is(err, wantErr) {
		t.Fatalf("network error = %v; want %v", err, wantErr)
	}
	if requestContext == nil || requestContext.Err() != context.Canceled {
		t.Fatalf("network context error = %v; want canceled", requestContext)
	}
}

// A real HTTP exchange checks the client's timeout across the cooldown wait.
func TestRetryAfterTransportWaitsOutsideClientTimeout(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	base := server.Client()
	base.Timeout = 50 * time.Millisecond
	client := newProviderClient(base)
	url := server.URL + "/logs/test/ct/v1/get-entries?start=0&end=255"
	resp, err := retryAfterDo(t.Context(), client, url)
	if err != nil {
		t.Fatal(err)
	}
	closeRetryAfterResponse(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first status = %d; want 429", resp.StatusCode)
	}

	started := time.Now()
	resp, err = retryAfterDo(t.Context(), client, url)
	if err != nil {
		t.Fatalf("retry after client timeout: %v", err)
	}
	closeRetryAfterResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d; want 200", resp.StatusCode)
	}
	if elapsed := time.Since(started); elapsed < 850*time.Millisecond {
		t.Fatalf("retry waited %v; want about one second", elapsed)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("server calls = %d; want 2", got)
	}
}

func TestRetryAfterTransportSharesCooldownAcrossParallelRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
			}
			return retryAfterResponse(http.StatusOK, ""), nil
		})}
		client := newProviderClient(base)
		url := "https://log.example/logs/test/ct/v1/get-entries?start=0&end=255"
		resp, err := retryAfterDo(t.Context(), client, url)
		if err != nil {
			t.Fatal(err)
		}
		closeRetryAfterResponse(t, resp)

		type result struct {
			status int
			err    error
		}
		const parallel = 4
		results := make(chan result, parallel)
		for range parallel {
			go func() {
				resp, err := retryAfterDo(t.Context(), client, url)
				if err == nil {
					err = resp.Body.Close()
					results <- result{status: resp.StatusCode, err: err}
				} else {
					results <- result{err: err}
				}
			}()
		}
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("network calls during cooldown = %d; want 1", got)
		}
		for range parallel {
			got := <-results
			if got.err != nil || got.status != http.StatusOK {
				t.Fatalf("parallel retry = %+v; want 200", got)
			}
		}
		if got := calls.Load(); got != parallel+1 {
			t.Fatalf("network calls after cooldown = %d; want %d", got, parallel+1)
		}
	})
}

func TestRetryAfterTransportKeepsLongestDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		started := make(chan struct{}, 3)
		releaseOne := make(chan struct{})
		releaseTwo := make(chan struct{})
		releaseThree := make(chan struct{})
		base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
			n := calls.Add(1)
			started <- struct{}{}
			switch n {
			case 1:
				<-releaseOne
				return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
			case 2:
				<-releaseTwo
				return retryAfterResponse(http.StatusTooManyRequests, "2"), nil
			}
			<-releaseThree
			return retryAfterResponse(http.StatusOK, ""), nil
		})}
		client := newProviderClient(base)
		url := "https://log.example/logs/test/ct/v1/get-entries"
		results := make(chan error, 3)
		for range 3 {
			go func() {
				resp, err := retryAfterDo(t.Context(), client, url)
				if err == nil {
					err = resp.Body.Close()
				}
				results <- err
			}()
		}
		<-started
		<-started
		<-started
		close(releaseTwo)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		close(releaseThree)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		close(releaseOne)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		transport := client.Transport.(*retryAfterTransport)
		transport.mu.Lock()
		until := transport.until["https://log.example/logs/test/ct/v1/get-entries"]
		transport.mu.Unlock()
		if remaining := time.Until(until); remaining < 1500*time.Millisecond {
			t.Fatalf("remaining cooldown = %v; want longer 2s deadline", remaining)
		}
	})
}

func TestRetryAfterTransportScopesRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const entriesURL = "https://log.example/logs/test/ct/v1/get-entries"
		const headURL = "https://log.example/logs/test/ct/v1/get-sth"
		var calls atomic.Int64
		base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
			}
			return retryAfterResponse(http.StatusOK, ""), nil
		})}
		head := newProviderClient(base)
		resp, err := retryAfterDo(t.Context(), head, entriesURL)
		if err != nil {
			t.Fatal(err)
		}
		closeRetryAfterResponse(t, resp)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if _, err := retryAfterDo(ctx, head, entriesURL); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("same endpoint during cooldown: %v; want deadline", err)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("same endpoint network calls = %d; want 1", got)
		}
		resp, err = retryAfterDo(t.Context(), head, headURL)
		if err != nil {
			t.Fatalf("get-sth should proceed: %v", err)
		}
		closeRetryAfterResponse(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("get-sth status = %d; want 200", resp.StatusCode)
		}

		tail := newProviderClient(base)
		resp, err = retryAfterDo(t.Context(), tail, entriesURL)
		if err != nil {
			t.Fatalf("independent tail client should proceed: %v", err)
		}
		closeRetryAfterResponse(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tail status = %d; want 200", resp.StatusCode)
		}
	})
}

func TestRetryAfterTransportSharesTileCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return retryAfterResponse(http.StatusServiceUnavailable, "1"), nil
		})}
		client := newProviderClient(base)
		resp, err := retryAfterDo(t.Context(), client, "https://log.example/logs/test/tile/data/1")
		if err != nil {
			t.Fatal(err)
		}
		closeRetryAfterResponse(t, resp)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if _, err := retryAfterDo(ctx, client, "https://log.example/logs/test/tile/data/2"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("second tile during cooldown: %v; want deadline", err)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("tile network calls during cooldown = %d; want 1", got)
		}
	})
}

func TestRetryAfterTransportGatesHeadRequests(t *testing.T) {
	for _, path := range []string{"/logs/test/ct/v1/get-sth", "/logs/test/checkpoint"} {
		t.Run(path, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int64
				base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
				})}
				client := newProviderClient(base)
				url := "https://log.example" + path
				resp, err := retryAfterDo(t.Context(), client, url)
				if err != nil {
					t.Fatal(err)
				}
				closeRetryAfterResponse(t, resp)
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				defer cancel()
				if _, err := retryAfterDo(ctx, client, url); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("head request during cooldown: %v; want deadline", err)
				}
				if got := calls.Load(); got != 1 {
					t.Fatalf("head network calls during cooldown = %d; want 1", got)
				}
			})
		})
	}
}

func TestRetryAfterTransportCancelsCooldownWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		base := &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
		})}
		client := newProviderClient(base)
		url := "https://log.example/logs/test/ct/v1/get-entries"
		resp, err := retryAfterDo(t.Context(), client, url)
		if err != nil {
			t.Fatal(err)
		}
		closeRetryAfterResponse(t, resp)
		ctx, cancel := context.WithCancel(t.Context())
		results := make(chan error, 1)
		go func() {
			_, err := retryAfterDo(ctx, client, url)
			results <- err
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled wait = %v; want context canceled", err)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("network calls after cancel = %d; want 1", got)
		}
	})
}

func TestRetryAfterTransportTimesOutResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	base := server.Client()
	base.Timeout = 50 * time.Millisecond
	client := newProviderClient(base)
	resp, err := retryAfterDo(t.Context(), client, server.URL+"/logs/test/ct/v1/get-entries")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("body read succeeded after timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("body timeout took %v; want near 50ms", elapsed)
	}
	closeRetryAfterResponse(t, resp)
}

func TestRetryAfterTransportAllowsEmptyResponseBody(t *testing.T) {
	base := &http.Client{
		Timeout: time.Second,
		Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}, nil
		}),
	}
	client := newProviderClient(base)
	resp, err := retryAfterDo(t.Context(), client, "https://log.example/logs/test/ct/v1/get-sth")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil || len(data) != 0 {
		t.Fatalf("empty response body: %q, %v", data, err)
	}
	closeRetryAfterResponse(t, resp)
}
