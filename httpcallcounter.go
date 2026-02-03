package certstream

import (
	"maps"
	"net/http"
	"strings"
	"sync"
)

var httpCallsMu sync.Mutex
var httpCallsMap map[string]int64 = map[string]int64{}

type httpCallCounter struct {
	next http.RoundTripper
}

func (sct httpCallCounter) RoundTrip(req *http.Request) (*http.Response, error) {
	mapkey := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	for _, cutoff := range []string{"/ct/", "/tile/", "/checkpoint"} {
		if idx := strings.Index(mapkey, cutoff); idx != -1 {
			mapkey = mapkey[:idx+1]
			break
		}
	}
	httpCallsMu.Lock()
	httpCallsMap[mapkey]++
	httpCallsMu.Unlock()
	return sct.next.RoundTrip(req)
}

func GetHTTPCallsMap() (m map[string]int64) {
	httpCallsMu.Lock()
	m = maps.Clone(httpCallsMap)
	httpCallsMu.Unlock()
	return
}

func GetHTTPCalls(s string) (n int64) {
	httpCallsMu.Lock()
	n = httpCallsMap[s]
	httpCallsMu.Unlock()
	return
}
