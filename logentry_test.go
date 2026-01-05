package certstream

import (
	"slices"
	"testing"
)

func TestLogEntryIndexNilCases(t *testing.T) {
	var le LogEntry
	if got := le.Index(); got != -1 {
		t.Fatalf("Index() on zero LogEntry = %d, want -1", got)
	}
}

func TestLogEntryIndexFromCT(t *testing.T) {
	le := LogEntry{
		LogIndex: 12345,
	}
	if got := le.Index(); got != 12345 {
		t.Fatalf("Index() = %d, want 12345", got)
	}
}

func TestLogEntryCertNilCases(t *testing.T) {
	var le LogEntry
	if le.Cert() != nil {
		t.Fatalf("Cert() on zero LogEntry should be nil")
	}
	le = LogEntry{LogIndex: 1}
	if le.Cert() != nil {
		t.Fatalf("Cert() with LogIndex only should be nil")
	}
}

// Smoke test for String() not panicking and containing some key fields.
func TestLogEntryStringStable(t *testing.T) {
	le := LogEntry{
		LogIndex:   7,
		Historical: true,
	}
	s := le.String()
	if s == "" {
		t.Fatalf("String() returned empty")
	}
	// Not asserting exact formatting, just presence of index information.
	if !slices.Contains([]rune(s), '7') {
		t.Fatalf("String() = %q; expected to mention index 7", s)
	}
}
