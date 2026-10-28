package certstream

import "testing"

func TestReverseBackfillStart(t *testing.T) {
	oldBatchSize := LogBatchSize
	t.Cleanup(func() { LogBatchSize = oldBatchSize })
	LogBatchSize = 256
	tests := []struct {
		name     string
		minIndex int64
		tiled    bool
		want     int64
	}{
		{"aligned end", 12800, true, 0},
		{"unaligned first window", 12500, true, 0},
		{"second window", 25600, true, 12800},
		{"new window", 12801, true, 12800},
		{"small first window", 500, true, 0},
		{"raw window", 12500, false, 11264},
		{"raw aligned window", 12288, false, 11264},
		{"raw first window samples enough entries", 1025, false, 0},
		{"raw first entry", 1, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverseBackfillStart(tt.minIndex, tt.tiled); got != tt.want {
				t.Fatalf("reverseBackfillStart(%d, %v)=%d, want %d", tt.minIndex, tt.tiled, got, tt.want)
			}
		})
	}
	LogBatchSize = 1000
	if got := reverseBackfillStart(12500, false); got != 11000 {
		t.Fatalf("raw unaligned batch size start=%d, want 11000", got)
	}
	if got := reverseBackfillStart(12500, true); got != 0 {
		t.Fatalf("tiled start=%d, want 0", got)
	}
	LogBatchSize = 2000
	if got := reverseBackfillStart(5024, false); got != 2000 {
		t.Fatalf("raw larger batch size start=%d, want 2000", got)
	}
}
