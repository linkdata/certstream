package certstream

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
)

var ErrToggledLoggerPathEmpty = errors.New("toggled logger path empty")
var ErrToggledLoggerToggleMissing = errors.New("toggled logger toggle missing")
var ErrToggledLogOpen = errors.New("toggled log open failed")

type errToggledLogOpen struct {
	err error
}

func (e errToggledLogOpen) Error() string {
	return ErrToggledLogOpen.Error() + ": " + e.err.Error()
}

func (e errToggledLogOpen) Unwrap() error {
	return e.err
}

func (e errToggledLogOpen) Is(target error) bool {
	return target == ErrToggledLogOpen
}

type toggledHandler struct {
	toggle  *atomic.Bool
	handler slog.Handler
}

func newToggledHandler(toggle *atomic.Bool, handler slog.Handler) slog.Handler {
	return &toggledHandler{toggle: toggle, handler: handler}
}

func (th *toggledHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return th.toggle.Load() && th.handler.Enabled(ctx, level)
}

func (th *toggledHandler) Handle(ctx context.Context, record slog.Record) (err error) {
	if th.toggle.Load() {
		err = th.handler.Handle(ctx, record)
	}
	return
}

func (th *toggledHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handler := th.handler.WithAttrs(attrs)
	return &toggledHandler{toggle: th.toggle, handler: handler}
}

func (th *toggledHandler) WithGroup(name string) slog.Handler {
	handler := th.handler.WithGroup(name)
	return &toggledHandler{toggle: th.toggle, handler: handler}
}

func newToggledLogger(filepath string, toggle *atomic.Bool) (l *slog.Logger, err error) {
	err = ErrToggledLoggerPathEmpty
	if filepath != "" {
		err = ErrToggledLoggerToggleMissing
		if toggle != nil {
			var file *os.File
			file, err = os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				handler := newToggledHandler(toggle, slog.NewTextHandler(file, nil))
				l = slog.New(handler)
			} else {
				err = errToggledLogOpen{err: err}
			}
		}
	}
	return
}
