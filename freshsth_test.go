package certstream

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFreshSTHTransportAddsNonce(t *testing.T) {
	seen := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	var log bytes.Buffer
	client := server.Client()
	client.Transport = freshSTHTransport{next: newHeadLogTransport(client.Transport, &log)}
	urls := []string{
		server.URL + "/log/ct/v1/get-sth?existing=a%2Bb&flag",
		server.URL + "/log/ct/v1/get-sth?",
	}
	nonces := make(map[string]bool)
	for _, target := range urls {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		originalURL := req.URL.String()
		originalRawQuery := req.URL.RawQuery
		originalForceQuery := req.URL.ForceQuery
		for range 2 {
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			got := <-seen
			parsed, err := url.ParseRequestURI(got)
			if err != nil {
				t.Fatalf("ParseRequestURI(%q): %v", got, err)
			}
			nonce := parsed.Query().Get("cache_nonce")
			if nonce == "" || nonces[nonce] {
				t.Fatalf("cache nonce missing or repeated: %q", got)
			}
			nonces[nonce] = true
			if originalRawQuery != "" && !strings.HasPrefix(parsed.RawQuery, originalRawQuery+"&cache_nonce=") {
				t.Fatalf("query changed: %q", parsed.RawQuery)
			}
			if req.URL.String() != originalURL || req.URL.RawQuery != originalRawQuery || req.URL.ForceQuery != originalForceQuery {
				t.Fatalf("request URL mutated: %q", req.URL)
			}
			if !strings.Contains(log.String(), got) {
				t.Fatalf("head request log does not contain sent URL %q: %q", got, log.String())
			}
		}
	}
}

func TestFreshSTHTransportLeavesOtherRequests(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Transport = freshSTHTransport{next: client.Transport}
	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"entries", http.MethodGet, "/log/ct/v1/get-entries?start=1&end=2"},
		{"checkpoint", http.MethodGet, "/log/checkpoint?existing=yes"},
		{"post sth", http.MethodPost, "/log/ct/v1/get-sth?existing=yes"},
		{"other path", http.MethodGet, "/log/ct/v1/get-sth/extra?existing=yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tc.method, server.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if got := <-seen; got != tc.path {
				t.Fatalf("request URI = %q, want %q", got, tc.path)
			}
		})
	}
}
