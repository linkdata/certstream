package certstream

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
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
		method := ""
		uri := ""
		if req != nil {
			method = req.Method
			if req.URL != nil {
				uri = req.URL.Path
				if raw := req.URL.RawQuery; raw != "" {
					uri += "?" + raw
				}
			}
		}
		result := "error: missing response"
		if err != nil {
			result = "error: " + err.Error()
		}
		if err == nil && resp != nil {
			result = strconv.Itoa(resp.StatusCode)
		}
		tlt.mu.Lock()
		_, _ = fmt.Fprintf(tlt.writer, "%s %s %s %s\n", time.Now().UTC().Format(time.RFC3339), method, uri, result)
		tlt.mu.Unlock()
	}
}
