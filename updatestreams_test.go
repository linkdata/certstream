package certstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

type testLogListTransport struct {
	http.RoundTripper
	list []byte
}

func (tr testLogListTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() == loglist3.AllLogListURL {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(tr.list)), Header: make(http.Header), Request: r}, nil
	}
	return tr.RoundTripper.RoundTrip(r)
}

func TestUpdateStreamsWithoutDatabase(t *testing.T) {
	requests := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- r.URL.Path:
		default:
		}
		// A temporarily unavailable log keeps both readers running through refresh.
		http.Error(w, "retry", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	list, err := loglist3.NewFromJSON([]byte(sampleLogData))
	if err != nil {
		t.Fatal(err)
	}
	classic := list.Operators[0].Logs[1]
	classic.URL = srv.URL + "/classic/"
	tiled := newTestTiledLog(t)
	tiled.MonitoringURL = srv.URL + "/tiled/"
	tiled.State = classic.State
	list.Operators = []*loglist3.Operator{{Name: "Test", Email: []string{"ct@example.com"}, Logs: []*loglist3.Log{classic}, TiledLogs: []*loglist3.TiledLog{tiled}}}
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig()
	cfg.DataDir = ""
	cs := &CertStream{
		Config: *cfg,
		HeadClient: &http.Client{Transport: testLogListTransport{
			RoundTripper: srv.Client().Transport, list: data,
		}},
		operators: make(map[string]*LogOperator),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	wg.Add(1)
	if err := cs.updateStreams(ctx, &wg); err != nil {
		t.Fatal(err)
	}
	operators := cs.Operators()
	if len(operators) != 1 || cs.CountStreams() != 2 {
		t.Fatalf("operators=%d streams=%d, want one operator with two streams", len(operators), cs.CountStreams())
	}
	streams := operators[0].Streams()
	for _, stream := range streams {
		if stream.LogOperator != operators[0] {
			t.Fatal("classic and tiled logs do not share their registered operator")
		}
	}
	seen := make(map[string]bool)
	for len(seen) < 2 {
		select {
		case path := <-requests:
			switch path {
			case "/classic/ct/v1/get-sth", "/tiled/checkpoint":
				seen[path] = true
			default:
				t.Fatalf("unexpected reader request: %s", path)
			}
		case <-ctx.Done():
			t.Fatalf("readers did not request both logs: %v", seen)
		}
	}
	wg.Add(1)
	if err := cs.updateStreams(ctx, &wg); err != nil {
		t.Fatal(err)
	}
	if refreshed := cs.Operators(); !slices.Equal(refreshed, operators) || !slices.Equal(refreshed[0].Streams(), streams) || cs.CountStreams() != 2 {
		t.Fatal("refresh replaced or duplicated the registered operator or streams")
	}
}
