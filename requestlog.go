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
var ErrHeadLogOpen = errors.New("head log open failed")

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

type errHeadLogOpen struct {
	err error
}

func (e errHeadLogOpen) Error() string {
	return ErrHeadLogOpen.Error() + ": " + e.err.Error()
}

func (e errHeadLogOpen) Unwrap() error {
	return e.err
}

func (e errHeadLogOpen) Is(target error) bool {
	return target == ErrHeadLogOpen
}

type requestLogTransport struct {
	next   http.RoundTripper
	writer io.Writer
	mu     sync.Mutex
}

type tailLogTransport = requestLogTransport
type headLogTransport = requestLogTransport

func newRequestLogTransport(next http.RoundTripper, writer io.Writer) (rlt *requestLogTransport) {
	if next != nil && writer != nil {
		rlt = &requestLogTransport{next: next, writer: writer}
	}
	return
}

func newTailLogTransport(next http.RoundTripper, writer io.Writer) (tlt *tailLogTransport) {
	tlt = newRequestLogTransport(next, writer)
	return
}

func newHeadLogTransport(next http.RoundTripper, writer io.Writer) (hlt *headLogTransport) {
	hlt = newRequestLogTransport(next, writer)
	return
}

func (rlt *requestLogTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if rlt != nil {
		resp, err = rlt.next.RoundTrip(req)
		rlt.logRequest(req, resp, err)
	}
	return
}

func (rlt *requestLogTransport) logRequest(req *http.Request, resp *http.Response, err error) {
	if rlt != nil && rlt.writer != nil {
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
			rlt.mu.Lock()
			_, _ = fmt.Fprintf(rlt.writer, "%s %s %s://%s%s (%d) => %q (%d)\n",
				time.Now().UTC().Format(time.RFC3339), method, scheme, host, uri, reqcl, result, respcl)
			rlt.mu.Unlock()
		}
	}
}
