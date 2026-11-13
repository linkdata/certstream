package certstream

import (
	"context"
	"testing"
	"time"

	"github.com/linkdata/certstream/internal/testpg"
)

func TestPostgresFixturesIsolateDataAndCleanup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	first := testpg.NewDatabase(ctx, t)
	conn := testpg.Connect(ctx, t, first)
	if _, err := conn.Exec(ctx, `CREATE TABLE fixture_marker (id integer)`); err != nil {
		t.Fatal(err)
	}
	var secondName string
	t.Run("second", func(t *testing.T) {
		secondCtx, stop := context.WithTimeout(t.Context(), 3*time.Minute)
		defer stop()
		second := testpg.NewDatabase(secondCtx, t)
		secondName = second.Name
		other := testpg.Connect(secondCtx, t, second)
		var exists bool
		if err := other.QueryRow(secondCtx, `SELECT to_regclass('public.fixture_marker') IS NOT NULL`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("fixture data leaked into another database")
		}
	})
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, secondName).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("finished fixture database was not removed")
	}
}
