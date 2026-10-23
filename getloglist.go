package certstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/certificate-transparency-go/loglist3"
)

// getLogList fetches and parses an HTTP 200 CT log list.
//
// Usually you would pass loglist3.AllLogListURL for the listUrl.
func getLogList(ctx context.Context, httpClient *http.Client, listUrl string) (logList *loglist3.LogList, err error) {
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, listUrl, nil); err == nil {
		var resp *http.Response
		if resp, err = httpClient.Do(req); err == nil {
			defer func() { err = errors.Join(err, resp.Body.Close()) }()
			if resp.StatusCode == http.StatusOK {
				var b []byte
				if b, err = io.ReadAll(resp.Body); err == nil {
					logList, err = loglist3.NewFromJSON(b)
				}
			} else {
				err = fmt.Errorf("log list HTTP status %d", resp.StatusCode)
			}
		}
	}
	return
}
