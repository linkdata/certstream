package certstream

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLogStreamBackoffSharesAcrossCalls(t *testing.T) {
	bo := newLogStreamBackoff(10*time.Millisecond, 10*time.Millisecond, 2, false)
	now := time.Now()
	bo.nowFn = func() time.Time {
		return now
	}
	var sleeps []time.Duration
	bo.sleepFn = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(t.Context())
	attempts := 0
	err := bo.Retry(ctx, func() error {
		attempts++
		if attempts == 1 {
			cancel()
			return wrapLogStreamRetryable(errors.New("retry"))
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want %v", err, context.Canceled)
	}
	if bo.next.IsZero() {
		t.Fatalf("expected backoff next to be set")
	}

	sleeps = nil
	err = bo.Retry(t.Context(), func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("Retry error: %v", err)
	}
	if got, want := len(sleeps), 1; got != want {
		t.Fatalf("sleep calls = %d, want %d", got, want)
	}
	if got, want := sleeps[0], 10*time.Millisecond; got != want {
		t.Fatalf("sleep duration = %v, want %v", got, want)
	}
}
