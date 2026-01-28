package certstream

import (
	"errors"
	"testing"

	"github.com/google/certificate-transparency-go/jsonclient"
)

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
		LogOperator: &LogOperator{},
	}
	if ls.handleStreamError(errors.New("tile/1/000: unexpected status code 404"), "Entries") {
		t.Fatalf("handleStreamError returned fatal for 404")
	}
}
