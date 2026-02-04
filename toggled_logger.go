package certstream

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

type lazyFileWriter struct {
	path string
	perm os.FileMode
}

func newLazyFileWriter(path string) *lazyFileWriter {
	return &lazyFileWriter{
		path: path,
		perm: 0o644,
	}
}

func (lw *lazyFileWriter) Write(p []byte) (n int, err error) {
	var file *os.File
	if file, err = os.OpenFile(lw.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, lw.perm); err == nil {
		defer file.Close()
		n, err = file.Write(p)
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
	return th.toggle.Load()
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
