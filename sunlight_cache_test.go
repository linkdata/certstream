package certstream

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneCacheFiles(t *testing.T) {
	tempDir := t.TempDir()
	oldDir := filepath.Join(tempDir, "old")
	oldPath := filepath.Join(oldDir, "old.txt")
	newPath := filepath.Join(tempDir, "new.txt")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(oldPath, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile old: %v", err)
	}
	if err := os.WriteFile(newPath, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile new: %v", err)
	}

	now := time.Now()
	oldTime := now.Add(-2 * time.Hour)
	newTime := now.Add(-30 * time.Minute)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes old: %v", err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatalf("Chtimes new: %v", err)
	}

	removed, err := pruneCacheFiles(tempDir, time.Hour, now)
	if err != nil {
		t.Fatalf("pruneCacheFiles: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d; want 1", removed)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("old file exists or Stat error: %v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("new file missing: %v", err)
	}
}
