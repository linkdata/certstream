package certstream

import "testing"

func TestCreateSchemaDropsLegacyGapObjects(t *testing.T) {
	ctx, db, _ := setupSelectGapsDB(t)
	if _, err := db.Exec(ctx, db.Pfx(`
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

	check := func(want bool) {
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
		if typeExists != want || functionExists != want || procedureExists != want {
			t.Fatalf("legacy objects exist: type=%t function=%t procedure=%t, want all %t",
				typeExists, functionExists, procedureExists, want)
		}
	}
	check(true)
	if _, err := db.Exec(ctx, db.Pfx(CreateSchema)); err != nil {
		t.Fatal(err)
	}
	check(false)
}
