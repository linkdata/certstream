package certstream

import (
	"fmt"
	"time"
)

type errLogIdle struct {
	Since time.Time
}

func (err errLogIdle) Error() string {
	return fmt.Sprintf("log idle since %v", err.Since.Round(time.Second))
}

var ErrLogIdle errLogIdle
