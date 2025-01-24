package certstream

type wrappedErr struct {
	err error
	msg string
}

func (we wrappedErr) Error() string {
	return we.msg + ": " + we.err.Error()
}

func (we wrappedErr) Unwrap() error {
	return we.err
}

func wrapErr(err error, msg string) error {
	if err == nil {
		return nil
	}
	return wrappedErr{err: err, msg: msg}
}
