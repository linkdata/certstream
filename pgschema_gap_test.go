package certstream

import "testing"

func TestCreateSchemaReplacesLegacyGapFunction(t *testing.T) {
	ctx, db, _ := setupSelectGapsDB(t)
	if _, err := db.Exec(ctx, db.Pfx(`
DROP FUNCTION CERTDB_findgap(integer, bigint, bigint);
CREATE TYPE CERTDB_gap AS (start_gap bigint, end_gap bigint);
CREATE FUNCTION CERTDB_findgap(integer, bigint, bigint)
RETURNS CERTDB_gap LANGUAGE sql AS $$
  SELECT ROW(0::bigint, 0::bigint)::CERTDB_gap
$$;
CREATE PROCEDURE CERTDB_set_backfill_first_gap()
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM * FROM CERTDB_findgap(1, 0, 0);
END;
$$;
`)); err != nil {
		t.Fatal(err)
	}

	check := func(wantType, wantFunction, wantProcedure bool) {
		t.Helper()
		var typeExists, functionExists, procedureExists bool
		if err := db.QueryRow(
			ctx, `SELECT to_regtype($1) IS NOT NULL,
to_regprocedure($2) IS NOT NULL, to_regprocedure($3) IS NOT NULL`,
			db.Pfx("CERTDB_gap"),
			db.Pfx("CERTDB_findgap(integer,bigint,bigint)"),
			db.Pfx("CERTDB_set_backfill_first_gap()"),
		).Scan(&typeExists, &functionExists, &procedureExists); err != nil {
			t.Fatal(err)
		}
		if typeExists != wantType || functionExists != wantFunction || procedureExists != wantProcedure {
			t.Fatalf("gap objects: type=%t function=%t procedure=%t, want %t, %t, %t",
				typeExists, functionExists, procedureExists, wantType, wantFunction, wantProcedure)
		}
	}
	check(true, true, true)
	if _, err := db.Exec(ctx, db.Pfx(CreateSchema)); err != nil {
		t.Fatal(err)
	}
	check(false, true, false)
	rows, err := db.Query(ctx, db.Pfx(`SELECT gap_start, gap_end FROM CERTDB_findgap(1, 0, 0);`))
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var functionOID uint32
	if err := db.QueryRow(
		ctx, `SELECT to_regprocedure($1)::oid`,
		db.Pfx("CERTDB_findgap(integer,bigint,bigint)"),
	).Scan(&functionOID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, db.Pfx(CreateSchema)); err != nil {
		t.Fatal(err)
	}
	check(false, true, false)
	var repeatedOID uint32
	if err := db.QueryRow(
		ctx, `SELECT to_regprocedure($1)::oid`,
		db.Pfx("CERTDB_findgap(integer,bigint,bigint)"),
	).Scan(&repeatedOID); err != nil {
		t.Fatal(err)
	}
	if repeatedOID != functionOID {
		t.Fatalf("function OID changed from %d to %d", functionOID, repeatedOID)
	}
}

func TestFindGap(t *testing.T) {
	t.Parallel()

	ctx, db, _ := setupSelectGapsDB(t)
	var operatorID, streamID, otherStreamID int32
	if err := db.QueryRow(
		ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
		"op", "op@example.com",
	).Scan(&operatorID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.com/findgap", operatorID, &streamID); err != nil {
		t.Fatal(err)
	}
	if err := insertStream(ctx, db, "https://example.com/findgap-other", operatorID, &otherStreamID); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, streamID, []int64{1, 4, 7, 11}); err != nil {
		t.Fatal(err)
	}
	if err := insertEntries(ctx, db, otherStreamID, []int64{2, 3, 5, 6, 8, 9, 10}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		start, end int64
		want       []gap
	}{
		{"whole range", 1, 11, []gap{{2, 3}, {5, 6}, {8, 10}}},
		{"inclusive bounds", 4, 7, []gap{{5, 6}}},
		{"outside bounds", 2, 10, []gap{{5, 6}}},
		{"one entry", 11, 11, nil},
		{"no entries", 12, 20, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.Query(ctx, db.Pfx(`SELECT gap_start, gap_end FROM CERTDB_findgap($1, $2, $3);`),
				streamID, tc.start, tc.end)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()

			var got []gap
			for rows.Next() {
				var g gap
				if err := rows.Scan(&g.start, &g.end); err != nil {
					t.Fatal(err)
				}
				got = append(got, g)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !gapsEqual(got, tc.want) {
				t.Fatalf("gaps = %v, want %v", got, tc.want)
			}
		})
	}
}
