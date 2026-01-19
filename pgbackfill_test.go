package certstream

import "testing"

func TestPgDB_BackfillStartIndex_UsesStoredIndex(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-backfill"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{5, 6, 7}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				if _, err = db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream SET backfill_logindex = $1 WHERE id = $2;`),
					int64(42), streamID,
				); err != nil {
					t.Fatalf("update backfill_logindex failed: %v", err)
				} else {
					ls := &LogStream{Id: streamID}
					ls.LastIndex.Store(100)
					var minIndex int64
					var stored bool
					if minIndex, stored, err = db.backfillStartIndex(ctx, ls); err != nil {
						t.Fatalf("backfillStartIndex failed: %v", err)
					} else if !stored {
						t.Fatalf("stored = false, want true")
					} else if minIndex != 42 {
						t.Fatalf("minIndex = %d, want 42", minIndex)
					} else {
						if _, err = db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream SET backfill_logindex = 0 WHERE id = $1;`),
							streamID,
						); err != nil {
							t.Fatalf("clear backfill_logindex failed: %v", err)
						} else if minIndex, stored, err = db.backfillStartIndex(ctx, ls); err != nil {
							t.Fatalf("backfillStartIndex without stored failed: %v", err)
						} else if stored {
							t.Fatalf("stored = true, want false")
						} else if minIndex != 5 {
							t.Fatalf("minIndex = %d, want 5", minIndex)
						}
					}
				}
			}
		}
	}
}
