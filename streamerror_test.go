package certstream

import (
	"errors"
	"testing"
	"time"
)

func TestStreamErrorImplements(t *testing.T) {
	under := errors.New("kaboom")
	se := StreamError{When: time.Now(), Err: under}

	if se.Error() == "" {
		t.Fatalf("Error() returned empty string")
	}
	if !errors.Is(se, under) {
		t.Fatalf("errors.Is(StreamError, underlying) = false; want true")
	}
	if errors.Unwrap(se) != under {
		t.Fatalf("Unwrap() != underlying")
	}
}
