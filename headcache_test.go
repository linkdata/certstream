package certstream

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHeadFreshness(t *testing.T) {
	now := time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC)
	date := now.Add(-40 * time.Second).Format(http.TimeFormat)
	expires := now.Add(20 * time.Second).Format(http.TimeFormat)
	tests := []struct {
		name         string
		cacheControl []string
		age          string
		date         string
		expires      string
		want         time.Duration
	}{
		{name: "missing headers"},
		{name: "max age", cacheControl: []string{"public, max-age=60"}, want: time.Minute},
		{name: "quoted max age", cacheControl: []string{`max-age="60"`}, want: time.Minute},
		{name: "broken quoted max age", cacheControl: []string{`max-age="60`}},
		{name: "cached age", cacheControl: []string{"max-age=60"}, age: "20", want: 40 * time.Second},
		{name: "listed age", cacheControl: []string{"max-age=60"}, age: "20, 40", want: 40 * time.Second},
		{name: "apparent age", cacheControl: []string{"max-age=60"}, date: date, want: 20 * time.Second},
		{name: "greater age", cacheControl: []string{"max-age=60"}, date: date, age: "50", want: 10 * time.Second},
		{name: "expires", date: date, expires: expires, age: "10", want: 20 * time.Second},
		{name: "expires without date", expires: expires, want: 20 * time.Second},
		{name: "max age overrides expires", cacheControl: []string{"max-age=60"}, expires: expires, want: time.Minute},
		{name: "no cache", cacheControl: []string{"max-age=60, no-cache"}},
		{name: "no store", cacheControl: []string{"no-store, max-age=60"}},
		{name: "invalid max age", cacheControl: []string{"max-age=bad"}, expires: expires},
		{name: "duplicate max age", cacheControl: []string{"max-age=60", "max-age=30"}},
		{name: "shared max age ignored", cacheControl: []string{"s-maxage=600, max-age=10"}, want: 10 * time.Second},
		{name: "shared max age only", cacheControl: []string{"s-maxage=600"}},
		{name: "expired age", cacheControl: []string{"max-age=10"}, age: "20"},
		{name: "invalid age", cacheControl: []string{"max-age=60"}, age: "bad"},
		{name: "invalid date", cacheControl: []string{"max-age=60"}, date: "bad"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			for _, line := range tc.cacheControl {
				header.Add("Cache-Control", line)
			}
			if tc.age != "" {
				header.Set("Age", tc.age)
			}
			if tc.date != "" {
				header.Set("Date", tc.date)
			}
			if tc.expires != "" {
				header.Set("Expires", tc.expires)
			}
			if got := headFreshness(header, now); got != tc.want {
				t.Fatalf("headFreshness = %v; want %v", got, tc.want)
			}
		})
	}
}

type headCacheRoundTripFunc func(*http.Request) (*http.Response, error)

func (f headCacheRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHeadCacheTransportCapturesMarkedResponses(t *testing.T) {
	base := headCacheRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Cache-Control", "max-age=60")
		status := http.StatusOK
		if req.URL.Path == "/error" {
			status = http.StatusTooManyRequests
		}
		return &http.Response{
			StatusCode: status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("body")),
			Request:    req,
		}, nil
	})
	client := &http.Client{Transport: headCacheTransport{next: base}}
	fetch := func(ctx context.Context, path string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err = resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}

	var capture headPollCache
	fetch(t.Context(), "/ct/v1/get-sth")
	if !capture.until.IsZero() {
		t.Fatal("unmarked response was captured")
	}
	fetch(withHeadPollCache(t.Context(), &capture), "/error")
	if !capture.until.IsZero() {
		t.Fatal("error response was captured")
	}
	fetch(withHeadPollCache(t.Context(), &capture), "/checkpoint")
	if capture.until.IsZero() {
		t.Fatal("poll delay was not captured")
	}
	if got := capture.delay(10 * time.Second); got < 55*time.Second || got > time.Minute {
		t.Fatalf("capture delay = %v; want near one minute", got)
	}
}
