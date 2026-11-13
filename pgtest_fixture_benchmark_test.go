package certstream

import "testing"

// BenchmarkPostgresFixtureSetup measures another fixture after the first one.
//
// Run with -benchtime=1x -count=6 to release both fixtures between samples.
func BenchmarkPostgresFixtureSetup(b *testing.B) {
	b.ReportAllocs()
	setupSelectGapsDB(b)
	b.ResetTimer()
	for range b.N {
		setupSelectGapsDB(b)
	}
}
