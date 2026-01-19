package certstream

import (
	"errors"
	"testing"

	"github.com/google/certificate-transparency-go/jsonclient"
)

func TestStatusCodeFromError(t *testing.T) {
	code, ok := statusCodeFromError(jsonclient.RspError{
		Err:        errors.New("nope"),
		StatusCode: 404,
	})
	if !ok || code != 404 {
		t.Fatalf("statusCodeFromError(jsonclient) = %d, %t", code, ok)
	}

	code, ok = statusCodeFromError(errors.New("tile/1/000: unexpected status code 404"))
	if !ok || code != 404 {
		t.Fatalf("statusCodeFromError(string) = %d, %t", code, ok)
	}

	code, ok = statusCodeFromError(errors.New("no status here"))
	if ok {
		t.Fatalf("statusCodeFromError(no status) = %d, %t", code, ok)
	}
}

func TestHandleStreamErrorTreatsNotFoundAsTransient(t *testing.T) {
	ls := &LogStream{
		LogOperator: &LogOperator{},
	}
	if ls.handleStreamError(errors.New("tile/1/000: unexpected status code 404"), "Entries") {
		t.Fatalf("handleStreamError returned fatal for 404")
	}
}
