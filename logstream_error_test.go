package certstream

import (
	"context"
	"errors"
	"testing"

	"github.com/google/certificate-transparency-go/jsonclient"
)

type opaqueDeadlineError struct{}

func (opaqueDeadlineError) Error() string        { return "request canceled while reading body" }
func (opaqueDeadlineError) Is(target error) bool { return target == context.DeadlineExceeded }

func TestStatusCodeFromError(t *testing.T) {
	ls := &LogStream{
		LogOperator: &LogOperator{},
	}
	code := ls.statusCodeFromError(jsonclient.RspError{
		Err:        errors.New("nope"),
		StatusCode: 404,
	})
	if code != 404 {
		t.Fatalf("statusCodeFromError(jsonclient) = %d", code)
	}

	code = ls.statusCodeFromError(errors.New("tile/1/000: unexpected status code 404"))
	if code != 404 {
		t.Fatalf("statusCodeFromError(string) = %d", code)
	}

	code = ls.statusCodeFromError(errors.New("no status here"))
	if code != 0 {
		t.Fatalf("statusCodeFromError(no status) = %d", code)
	}
}

func TestHandleStreamErrorTreatsNotFoundAsTransient(t *testing.T) {
	ls := &LogStream{
		LogOperator: &LogOperator{
			CertStream: &CertStream{},
		},
	}
	if ls.handleStreamError(errors.New("tile/1/000: unexpected status code 404"), "Entries") {
		t.Fatalf("handleStreamError returned fatal for 404")
	}
}

func TestHandleStreamErrorTreatsBodyTimeoutAsTransient(t *testing.T) {
	ls := &LogStream{LogOperator: &LogOperator{CertStream: &CertStream{}}}
	err := jsonclient.RspError{Err: opaqueDeadlineError{}}
	for range MaxErrors + 1 {
		if ls.handleStreamError(err, "GetRawEntries") {
			t.Fatal("body timeout stopped stream")
		}
	}
	if ls.errcount != 0 {
		t.Fatalf("body timeouts counted as errors: %d", ls.errcount)
	}
}
