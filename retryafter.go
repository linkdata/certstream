package certstream

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// retryAfterTransport shares a cooldown across one stream's matching requests.
//
// Head and tail clients have separate cooldowns. Classic endpoints have
// separate cooldowns, while a tiled log's tile paths share one. The client
// using this transport has no Client.Timeout; each network request gets the
// original timeout after the cooldown wait so a long Retry-After is usable.
type retryAfterTransport struct {
	next    http.RoundTripper
	timeout time.Duration
	mu      sync.Mutex
	until   map[string]time.Time
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelBody) Read(p []byte) (n int, err error) {
	n, err = body.ReadCloser.Read(p)
	if err != nil {
		body.cancel()
	}
	return
}

func (body *cancelBody) Close() (err error) {
	err = body.ReadCloser.Close()
	body.cancel()
	return
}

func newProviderClient(base *http.Client) *http.Client {
	next := base.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	return &http.Client{
		Transport:     &retryAfterTransport{next: next, timeout: base.Timeout, until: make(map[string]time.Time)},
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
	}
}

func retryAfterKey(u *url.URL) string {
	path := u.Path
	if idx := strings.LastIndex(path, "/tile/"); idx >= 0 {
		path = path[:idx+len("/tile/")]
	}
	return u.Scheme + "://" + u.Host + path
}

func retryAfterTime(value string, now time.Time) (until time.Time) {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds >= 0 && seconds <= int64((1<<63-1)/int64(time.Second)) {
			until = now.Add(time.Duration(seconds) * time.Second)
		}
	} else {
		if until, err = http.ParseTime(value); err != nil {
			// Skylight sends RFC1123 dates with UTC instead of HTTP's GMT.
			until, _ = time.Parse(time.RFC1123, value)
		}
	}
	if !until.After(now) {
		until = time.Time{}
	}
	return
}

func (transport *retryAfterTransport) wait(ctx context.Context, key string) (err error) {
	for err == nil {
		transport.mu.Lock()
		until := transport.until[key]
		transport.mu.Unlock()
		delay := time.Until(until)
		if delay <= 0 {
			return ctx.Err()
		}
		err = sleep(ctx, delay)
	}
	return
}

func (transport *retryAfterTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	key := retryAfterKey(req.URL)
	if err = transport.wait(req.Context(), key); err != nil {
		return
	}

	request := req
	var cancel context.CancelFunc
	if transport.timeout > 0 {
		var ctx context.Context
		ctx, cancel = context.WithTimeout(req.Context(), transport.timeout)
		request = req.Clone(ctx)
	}
	resp, err = transport.next.RoundTrip(request)
	if err != nil || resp == nil {
		if cancel != nil {
			cancel()
		}
		return
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		if until := retryAfterTime(resp.Header.Get("Retry-After"), time.Now()); !until.IsZero() {
			// Keep the operator's full deadline; cancellation still ends the wait.
			transport.mu.Lock()
			if until.After(transport.until[key]) {
				transport.until[key] = until
			}
			transport.mu.Unlock()
		}
	}
	if cancel != nil {
		if resp.Body != nil {
			resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
		} else {
			cancel()
		}
	}
	return
}
