package certstream

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

var ErrLogStreamRetryable = errors.New("logstream retryable")
var ErrSTHDiffTooLow = errors.New("STH diff too low")

type logStreamRetryableError struct {
	err error
}

func (e logStreamRetryableError) Error() string {
	return e.err.Error()
}

func (e logStreamRetryableError) Unwrap() error {
	return e.err
}

func (e logStreamRetryableError) Is(target error) bool {
	return target == ErrLogStreamRetryable
}

func wrapLogStreamRetryable(err error) (wrapped error) {
	if err != nil {
		wrapped = logStreamRetryableError{err: err}
	} else {
		wrapped = ErrLogStreamRetryable
	}
	return
}

type logStreamBackoff struct {
	mu      sync.Mutex
	min     time.Duration
	max     time.Duration
	factor  float64
	jitter  bool
	current time.Duration
	next    time.Time
	nowFn   func() time.Time
	sleepFn func(context.Context, time.Duration)
}

func newLogStreamBackoff(min, max time.Duration, factor float64, jitter bool) (bo *logStreamBackoff) {
	bo = &logStreamBackoff{
		min:     min,
		max:     max,
		factor:  factor,
		jitter:  jitter,
		nowFn:   time.Now,
		sleepFn: sleep,
	}
	return
}

func (b *logStreamBackoff) Retry(ctx context.Context, f func() error) (err error) {
	for err == nil {
		if err = b.wait(ctx); err == nil {
			if err = f(); err == nil {
				b.success()
				break
			}
			if errors.Is(err, ErrLogStreamRetryable) {
				b.backoff()
				err = nil
			}
		}
	}
	return
}

func (b *logStreamBackoff) wait(ctx context.Context) (err error) {
	if b != nil {
		if err = ctx.Err(); err == nil {
			b.mu.Lock()
			next := b.next
			b.mu.Unlock()
			if !next.IsZero() {
				delay := next.Sub(b.nowFn())
				if delay > 0 {
					b.sleepFn(ctx, delay)
					err = ctx.Err()
				}
			}
		}
	}
	return
}

func (b *logStreamBackoff) success() {
	if b != nil {
		b.mu.Lock()
		if b.factor > 0 {
			b.current = time.Duration(float64(b.current) / b.factor)
			if b.current < b.min {
				b.current = 0
			}
		}
		if b.current > 0 {
			b.next = b.nowFn().Add(b.current)
		} else {
			b.next = time.Time{}
		}
		b.mu.Unlock()
	}
}

func (b *logStreamBackoff) backoff() {
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()

		if b.current > 0 && b.factor > 0 {
			b.current = time.Duration(float64(b.current) * b.factor)
		}
		b.current = max(b.min, b.current)
		b.current = min(b.max, b.current)
		b.next = time.Time{}

		if b.current > 0 {
			delay := b.current
			if b.jitter {
				delay += time.Duration(rand.Int64N(int64(b.current))) /*#nosec G404*/
			}
			delay = min(b.max, delay)
			b.next = b.nowFn().Add(delay)
		}
	}
}
