package certstream

import (
	"fmt"
	"time"
)

type errorWithTime struct {
	When time.Time
	Err  error
}

func (ewt errorWithTime) Error() string {
	return fmt.Sprintf("%v %s", ewt.When.Format(time.DateTime), ewt.Err.Error())
}

func (ewt errorWithTime) Unwrap() error {
	return ewt.Err
}
