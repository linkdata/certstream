package certstream

import (
	"fmt"
	"time"
)

type StreamError struct {
	*LogStream
	When time.Time
	Err  error
}

func (ewt StreamError) Error() string {
	return fmt.Sprintf("%v %s", ewt.When.Format(time.DateTime), ewt.Err.Error())
}

func (ewt StreamError) Unwrap() error {
	return ewt.Err
}
