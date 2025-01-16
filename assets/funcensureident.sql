CREATE OR REPLACE FUNCTION CERTDB_ensure_ident(
	_org TEXT,
	_prov TEXT,
	_country TEXT
)
RETURNS BIGINT
LANGUAGE sql
BEGIN ATOMIC;
	WITH new_row AS (
		INSERT INTO CERTDB_ident (organization, province, country)
		VALUES (_org, _prov, _country)
		ON CONFLICT (organization, province, country) DO UPDATE SET country=_country
		RETURNING id
	) SELECT id FROM new_row; 
END;