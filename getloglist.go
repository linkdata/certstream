package certstream

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/google/certificate-transparency-go/loglist3"
	"golang.org/x/net/proxy"
)

// GetLogList fetches a CT log list from the given listUrl.
// Usually you would pass loglist3.AllLogListURL for the listUrl.
func GetLogList(ctx context.Context, cd proxy.ContextDialer, listUrl string) (logList *loglist3.LogList, err error) {
	if cd == nil {
		cd = &net.Dialer{}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: cd.DialContext,
		},
	}
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, listUrl, nil); err == nil {
		var resp *http.Response
		if resp, err = httpClient.Do(req); err == nil {
			var b []byte
			if b, err = io.ReadAll(resp.Body); err == nil {
				logList, err = loglist3.NewFromJSON(b)
			}
		}
	}
	return
}
