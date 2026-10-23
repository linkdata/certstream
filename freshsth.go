package certstream

import (
	"crypto/rand"
	"net/http"
	"strings"
)

type freshSTHTransport struct {
	next http.RoundTripper
}

func (tr freshSTHTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/ct/v1/get-sth") {
		return tr.next.RoundTrip(req)
	}

	// Some CT CDNs cache this endpoint for minutes, so each fetch needs a new URL.
	fresh := req.Clone(req.Context())
	if fresh.URL.RawQuery != "" {
		fresh.URL.RawQuery += "&"
	}
	fresh.URL.RawQuery += "cache_nonce=" + rand.Text()
	return tr.next.RoundTrip(fresh)
}
