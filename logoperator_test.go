package certstream

import "testing"

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
