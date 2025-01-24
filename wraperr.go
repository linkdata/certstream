package certstream

type wrapErr struct {
	err error
	msg string
}

func (we wrapErr) Error() string {
	return we.msg + ": " + we.err.Error()
}

func (we wrapErr) Unwrap() error {
	return we.err
}

func wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return wrapErr{err: err, msg: msg}
}
