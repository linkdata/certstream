CREATE OR REPLACE FUNCTION CERTDB_ensure_ident(
  _org TEXT, 
  _prov TEXT, 
  _country TEXT
)
RETURNS BIGINT
LANGUAGE sql
BEGIN ATOMIC;
	WITH _ensure_ident AS (
      INSERT INTO CERTDB_ident (organization, province, country)
      SELECT _org, _prov, _country
      WHERE NOT EXISTS (
        SELECT id FROM CERTDB_ident WHERE organization=_org AND province=_prov AND country=_country
      )
      RETURNING *
    )
	(
		SELECT id FROM CERTDB_ident WHERE organization=_org AND province=_prov AND country=_country
		UNION ALL
		SELECT id FROM _ensure_ident
	)
	LIMIT 1;
END;
