CREATE OR REPLACE FUNCTION CERTDB_ensure_domain_pk()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  _table regclass;
  _has_pk boolean;
BEGIN
  _table := to_regclass('CERTDB_domain');
  IF _table IS NOT NULL THEN
    SELECT EXISTS (
      SELECT 1
      FROM pg_constraint
      WHERE conrelid = _table
        AND contype = 'p'
    ) INTO _has_pk;
    IF NOT _has_pk THEN
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

      ALTER TABLE CERTDB_domain
        ADD PRIMARY KEY (cert, wild, www, domain, tld);

      DROP INDEX IF EXISTS CERTDB_domain_cert_idx;
    END IF;
  END IF;
END;
$$;
