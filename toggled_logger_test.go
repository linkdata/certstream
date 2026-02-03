package certstream

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func readLogFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(data)
}

func TestToggledLoggerToggle(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "toggle.log")

	var toggle atomic.Bool
	logger, err := newToggledLogger(logPath, &toggle)
	if err != nil {
		t.Fatalf("newToggledLogger: %v", err)
	}
	if logger == nil {
		t.Fatalf("newToggledLogger returned nil logger")
	}

	logger.Info("first", "state", "off")
	logText := readLogFile(t, logPath)
	if logText != "" {
		t.Fatalf("log output when toggle is false: %q", logText)
	}

	toggle.Store(true)
	logger.Info("second", "state", "on")
	logText = readLogFile(t, logPath)
	if !strings.Contains(logText, "second") || !strings.Contains(logText, "state=on") {
		t.Fatalf("log output missing expected fields: %q", logText)
	}

	toggle.Store(false)
	logger.Info("third", "state", "off-again")
	logText = readLogFile(t, logPath)
	if strings.Contains(logText, "third") {
		t.Fatalf("log output present after toggle off: %q", logText)
	}
}

func TestToggledLoggerErrors(t *testing.T) {
	var toggle atomic.Bool
	if _, err := newToggledLogger("", &toggle); !errors.Is(err, ErrToggledLoggerPathEmpty) {
		t.Fatalf("newToggledLogger path err = %v; want %v", err, ErrToggledLoggerPathEmpty)
	}
	if _, err := newToggledLogger("path.log", nil); !errors.Is(err, ErrToggledLoggerToggleMissing) {
		t.Fatalf("newToggledLogger toggle err = %v; want %v", err, ErrToggledLoggerToggleMissing)
	}

	tempDir := t.TempDir()
	if _, err := newToggledLogger(tempDir, &toggle); !errors.Is(err, ErrToggledLogOpen) {
		t.Fatalf("newToggledLogger open err = %v; want %v", err, ErrToggledLogOpen)
	}
}
