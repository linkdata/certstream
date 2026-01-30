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

	code = ls.statusCodeFromError(tileFetchError{statusCode: 404, url: "https://example.test/tile/entries/000"})
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
	if ls.handleStreamError(tileFetchError{statusCode: 404, url: "https://example.test/tile/entries/000"}, "Entries") {
		t.Fatalf("handleStreamError returned fatal for 404")
	}
}
