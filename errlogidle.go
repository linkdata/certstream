package certstream

import (
	"fmt"
	"time"
)

type errLogIdle struct {
	IdleTime time.Duration
}

func (err errLogIdle) Error() string {
	return fmt.Sprintf("log idle for %v", err.IdleTime)
}

var ErrLogIdle errLogIdle
