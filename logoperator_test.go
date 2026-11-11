package certstream

import (
	"net/http"
	"testing"
	"time"
)

func TestLogOperatorRawRequestDelay(t *testing.T) {
	lo := &LogOperator{}
	lo.Status429.Store(250)
	if got := lo.rawRequestDelay(true); got != 0 {
		t.Fatalf("old 429 count set raw delay to %v", got)
	}

	lo.addStatus(http.StatusTooManyRequests)
	if got := lo.rawRequestDelay(false); got != 32*time.Millisecond {
		t.Fatalf("head delay = %v, want 32ms", got)
	}
	if got := lo.rawRequestDelay(true); got != 64*time.Millisecond {
		t.Fatalf("historical delay = %v, want 64ms", got)
	}
	for range 32 {
		lo.rawRequestSucceeded()
	}
	if got := lo.rawRequestDelay(true); got != 0 {
		t.Fatalf("delay after successes = %v, want zero", got)
	}
	if got := lo.Status429.Load(); got != 251 {
		t.Fatalf("cumulative 429 count = %d, want 251", got)
	}

	for range 16 {
		lo.addStatus(http.StatusTooManyRequests)
	}
	if got := lo.rawRequestDelay(true); got != time.Second {
		t.Fatalf("capped historical delay = %v, want 1s", got)
	}
}

func TestGetStreamByIDMiss(t *testing.T) {
	stream := &LogStream{Id: 1}
	operator := &LogOperator{streams: map[string]*LogStream{"stream": stream}}
	if got := operator.GetStreamByID(1); got != stream {
		t.Fatalf("GetStreamByID(1) = %p, want %p", got, stream)
	}
	if got := operator.GetStreamByID(2); got != nil {
		t.Fatalf("GetStreamByID(2) = %p, want nil", got)
	}
	cs := &CertStream{operators: map[string]*LogOperator{"operator": operator}}
	if got := cs.GetLogStreamByID(1); got != stream {
		t.Fatalf("GetLogStreamByID(1) = %p, want %p", got, stream)
	}
	if got := cs.GetLogStreamByID(2); got != nil {
		t.Fatalf("GetLogStreamByID(2) = %p, want nil", got)
	}
}
