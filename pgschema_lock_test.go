package certstream

import (
	"context"
	"testing"
	"time"
)

func TestEnsureSchemaWithExistingStreamDoesNotWaitForReaders(t *testing.T) {
	ctx, db, _ := setupSelectGapsDB(t)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil {
			t.Error(err)
		}
	}()
	var count int
	if err := tx.QueryRow(ctx, db.Pfx(`SELECT COUNT(*) FROM CERTDB_stream`)).Scan(&count); err != nil {
		t.Fatal(err)
	}

	setupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ensureSchema(setupCtx, db.Pool, db.Pfx); err != nil {
		t.Fatalf("schema setup waited for a stream reader: %v", err)
	}
}
