package certstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

var ErrTailLogOpen = errors.New("tail log open failed")

type errTailLogOpen struct {
	err error
}

func (e errTailLogOpen) Error() string {
	return ErrTailLogOpen.Error() + ": " + e.err.Error()
}

func (e errTailLogOpen) Unwrap() error {
	return e.err
}

func (e errTailLogOpen) Is(target error) bool {
	return target == ErrTailLogOpen
}

type tailLogTransport struct {
	next   http.RoundTripper
	writer io.Writer
	mu     sync.Mutex
}

func newTailLogTransport(next http.RoundTripper, writer io.Writer) (tlt *tailLogTransport) {
	if next != nil && writer != nil {
		tlt = &tailLogTransport{next: next, writer: writer}
	}
	return
}

func (tlt *tailLogTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if tlt != nil {
		resp, err = tlt.next.RoundTrip(req)
		tlt.logRequest(req, resp, err)
	}
	return
}

func (tlt *tailLogTransport) logRequest(req *http.Request, resp *http.Response, err error) {
	if tlt != nil && tlt.writer != nil {
		if !errors.Is(err, context.Canceled) {
			var scheme, host, method, uri, result string
			reqcl := int64(-1)
			respcl := int64(-1)
			if req != nil {
				reqcl = req.ContentLength
				host = req.Host
				method = req.Method
				if req.URL != nil {
					scheme = req.URL.Scheme
					uri = req.URL.Path
					if raw := req.URL.RawQuery; raw != "" {
						uri += "?" + raw
					}
				}
				if resp != nil {
					if result = resp.Status; result == "" {
						result = fmt.Sprintf("%03d", resp.StatusCode)
					}
					respcl = resp.ContentLength
				} else {
					result = "000 missing response"
				}
			} else {
				result = "000 missing request"
			}
			if err != nil {
				result += "; " + err.Error()
			}
			tlt.mu.Lock()
			_, _ = fmt.Fprintf(tlt.writer, "%s %s %s://%s%s (%d) => %q (%d)\n",
				time.Now().UTC().Format(time.RFC3339), method, scheme, host, uri, reqcl, result, respcl)
			tlt.mu.Unlock()
		}
	}
}
