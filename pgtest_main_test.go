package certstream

import (
	"fmt"
	"os"
	"testing"

	"github.com/linkdata/certstream/internal/testpg"
)

// TestMain removes the shared PostgreSQL container after tests and benchmarks.
func TestMain(m *testing.M) {
	if handled, err := testpg.RunWatchdog(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	code := m.Run()
	if err := testpg.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}
