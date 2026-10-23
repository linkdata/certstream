package certstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

type fatalHeadTransport struct{}

func (fatalHeadTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrNoProgress
}

func TestLogStreamNaturalExitCancelsChildContext(t *testing.T) {
	cfg := NewConfig()
	cfg.DataDir = ""
	cs := &CertStream{
		Config:     *cfg,
		HeadClient: &http.Client{Transport: fatalHeadTransport{}},
		operators:  make(map[string]*LogOperator),
	}
	const url = "https://logs.example.test/"
	lo := &LogOperator{
		CertStream: cs,
		Domain:     OperatorDomain(url),
		streams:    make(map[string]*LogStream),
	}
	log := &loglist3.Log{URL: url}
	ls, err := lo.makeStream(log)
	if err != nil {
		t.Fatal(err)
	}
	// A reader can already have observed an index when a later head request fails.
	ls.LastIndex.Store(0)
	lo.streams[url] = ls
	cs.operators[lo.Domain] = lo
	streamCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ls.cancel = cancel
	ls.done = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go ls.run(streamCtx, &wg)
	select {
	case <-ls.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("reader did not stop after fatal HTTP error; errors = %v", lo.Errors())
	}
	if errs := lo.Errors(); len(errs) == 0 || !errors.Is(errs[0].Err, io.ErrNoProgress) {
		t.Fatalf("reader errors = %v, want io.ErrNoProgress", errs)
	}
	select {
	case <-streamCtx.Done():
	default:
		t.Fatal("reader exited without canceling its child context")
	}
	select {
	case <-t.Context().Done():
		t.Fatal("parent context canceled")
	default:
	}
}
