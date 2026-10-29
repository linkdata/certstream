package certstream

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

type retryAfterBenchmarkTransport struct {
	started time.Time
	calls   int
}

func (transport *retryAfterBenchmarkTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport.calls++
	status := http.StatusOK
	header := make(http.Header)
	if time.Since(transport.started) < 2*time.Second {
		status = http.StatusTooManyRequests
		header.Set("Retry-After", "2")
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     header,
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

// BenchmarkProviderRetryAfter measures retry time and HTTP calls during a
// two-second provider cooldown with the production exponential backoff.
func BenchmarkProviderRetryAfter(b *testing.B) {
	for _, mode := range []struct {
		name  string
		honor bool
	}{
		{name: "without_header"},
		{name: "honor_header", honor: true},
	} {
		b.Run(mode.name, func(b *testing.B) {
			calls := 0
			b.ReportAllocs()
			for range b.N {
				transport := &retryAfterBenchmarkTransport{started: time.Now()}
				client := &http.Client{Transport: transport}
				if mode.honor {
					client = newProviderClient(client)
				}
				backoff := newLogStreamBackoff(time.Second, 30*time.Second, 2, false)
				request, err := http.NewRequestWithContext(b.Context(), http.MethodGet, "https://log.example/ct/v1/get-entries?start=0&end=255", nil)
				if err != nil {
					b.Fatal(err)
				}
				err = backoff.Retry(b.Context(), func() error {
					response, err := client.Do(request)
					if err != nil {
						return err
					}
					if err = response.Body.Close(); err != nil {
						return err
					}
					if response.StatusCode != http.StatusOK {
						return wrapLogStreamRetryable(fmt.Errorf("HTTP %d", response.StatusCode))
					}
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
				calls += transport.calls
			}
			b.ReportMetric(float64(calls)/float64(b.N), "http-requests/op")
		})
	}
}
