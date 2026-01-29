package certstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type staticTransport struct {
	resp *http.Response
	err  error
}

func (st *staticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return st.resp, st.err
}

type noDialer struct{}

func (noDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("dial disabled")
}

func TestTailLogTransportLogsResponse(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "tail-log-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() {
		_ = file.Close()
	})
	req, err := http.NewRequest(http.MethodGet, "https://example.test/test/path?foo=bar&baz=qux", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	transport := newTailLogTransport(&staticTransport{
		resp: &http.Response{
			StatusCode:    http.StatusAccepted,
			Status:        "202 Accepted",
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("ok")),
			ContentLength: 2,
		},
	}, file)
	if transport == nil {
		t.Fatalf("newTailLogTransport returned nil")
	}
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	line := string(data)
	if !strings.Contains(line, "GET https://example.test/test/path?foo=bar&baz=qux (0) => \"202 Accepted\" (2)") {
		t.Fatalf("log line missing fields: %q", line)
	}
}

func TestTailLogTransportLogsError(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "tail-log-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() {
		_ = file.Close()
	})
	req, err := http.NewRequest(http.MethodPost, "https://example.test/error/path?bad=yes", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	wantErr := errors.New("synthetic failure")
	transport := newTailLogTransport(&staticTransport{
		err: wantErr,
	}, file)
	if transport == nil {
		t.Fatalf("newTailLogTransport returned nil")
	}
	if _, err := transport.RoundTrip(req); !errors.Is(err, wantErr) {
		t.Fatalf("RoundTrip err = %v; want %v", err, wantErr)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	line := string(data)
	if !strings.Contains(line, "POST https://example.test/error/path?bad=yes (0) => \"000 missing response; synthetic failure\" (-1)") {
		t.Fatalf("log line missing fields: %q", line)
	}
}

func TestStartOpensTailLogFile(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "tail.log")

	cfg := NewConfig()
	cfg.HeadDialer = noDialer{}
	cfg.TailDialer = noDialer{}
	cfg.TailLog = logPath

	wg := &sync.WaitGroup{}
	cs, err := Start(ctx, wg, cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if cs == nil {
		t.Fatalf("Start returned nil CertStream")
	}
	if cs.getTailLogFile() == nil {
		t.Fatalf("tail log file was not stored on CertStream")
	}
	if _, ok := cs.TailClient.Transport.(*tailLogTransport); !ok {
		t.Fatalf("TailClient transport = %T; want *tailLogTransport", cs.TailClient.Transport)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("tail log file missing: %v", err)
	}
	cancel()
	wg.Wait()
}

func TestStartOpensHeadLogFile(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "head.log")

	cfg := NewConfig()
	cfg.HeadDialer = noDialer{}
	cfg.TailDialer = noDialer{}
	cfg.HeadLog = logPath

	wg := &sync.WaitGroup{}
	cs, err := Start(ctx, wg, cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if cs == nil {
		t.Fatalf("Start returned nil CertStream")
	}
	if cs.getHeadLogFile() == nil {
		t.Fatalf("head log file was not stored on CertStream")
	}
	if _, ok := cs.HeadClient.Transport.(*headLogTransport); !ok {
		t.Fatalf("HeadClient transport = %T; want *headLogTransport", cs.HeadClient.Transport)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("head log file missing: %v", err)
	}
	cancel()
	wg.Wait()
}
