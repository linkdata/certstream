CREATE OR REPLACE FUNCTION CERTDB_delete_domain_duplicates()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  _table regclass;
BEGIN
  _table := to_regclass('CERTDB_domain');
  IF _table IS NOT NULL THEN
      WITH dupes AS (
        SELECT
          ctid,
          ROW_NUMBER() OVER (
            PARTITION BY cert, wild, www, domain, tld
            ORDER BY ctid
          ) AS rn
        FROM CERTDB_domain
      )
      DELETE FROM CERTDB_domain d
      USING dupes
      WHERE d.ctid = dupes.ctid
        AND dupes.rn > 1;
  END IF;
END;
$$;
