package certstream

import "testing"

func TestReverseBackfillStart(t *testing.T) {
	oldBatchSize := LogBatchSize
	t.Cleanup(func() { LogBatchSize = oldBatchSize })
	LogBatchSize = 1024
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
		{"raw window", 12500, false, 11476},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverseBackfillStart(tt.minIndex, tt.tiled); got != tt.want {
				t.Fatalf("reverseBackfillStart(%d, %v)=%d, want %d", tt.minIndex, tt.tiled, got, tt.want)
			}
		})
	}
	LogBatchSize = 1000
	if got := reverseBackfillStart(12500, false); got != 11500 {
		t.Fatalf("raw unaligned batch size start=%d, want 11500", got)
	}
	if got := reverseBackfillStart(12500, true); got != 0 {
		t.Fatalf("tiled start=%d, want 0", got)
	}
}
