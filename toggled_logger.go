package certstream

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
)

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

type lazyFileWriter struct {
	path string
	perm os.FileMode
	once sync.Once
	file *os.File
	err  error
}

func newLazyFileWriter(path string) *lazyFileWriter {
	return &lazyFileWriter{
		path: path,
		perm: 0o644,
	}
}

func (lw *lazyFileWriter) open() {
	lw.file, lw.err = os.OpenFile(lw.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, lw.perm)
}

func (lw *lazyFileWriter) Write(p []byte) (n int, err error) {
	lw.once.Do(lw.open)
	err = lw.err
	if err == nil {
		n, err = lw.file.Write(p)
	}
	if lw.err != nil {
		err = errToggledLogOpen{err: lw.err}
	}
	return
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

func newToggledLogger(filepath string, toggle *atomic.Bool) (l *slog.Logger) {
	handler := newToggledHandler(toggle, slog.NewTextHandler(newLazyFileWriter(filepath), nil))
	l = slog.New(handler)
	return
}
