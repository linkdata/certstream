package certstream

import (
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

func assertFileMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("expected log file to be missing at %s", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("Stat: %v", err)
	}
}

func TestToggledLoggerToggle(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "toggle.log")

	var toggle atomic.Bool
	logger := newToggledLogger(logPath, &toggle)
	if logger == nil {
		t.Fatalf("newToggledLogger returned nil logger")
	}

	logger.Info("first", "state", "off")
	assertFileMissing(t, logPath)

	toggle.Store(true)
	logger.Info("second", "state", "on")
	logText := readLogFile(t, logPath)
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
