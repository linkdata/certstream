CREATE OR REPLACE FUNCTION CERTDB_operator_id(
  s_name  text,
  s_email text
)
RETURNS integer
LANGUAGE sql
AS $$
WITH existing AS (
  SELECT id
  FROM CERTDB_operator
  WHERE name = $1 AND email = $2
),
upsert AS (
  INSERT INTO CERTDB_operator (name, email)
  SELECT $1, $2
  WHERE NOT EXISTS (SELECT 1 FROM existing)
  ON CONFLICT (name, email) DO UPDATE
    SET name = EXCLUDED.name  -- no-op update so RETURNING always works
  RETURNING id
)
SELECT id FROM upsert
UNION ALL
SELECT id FROM existing
LIMIT 1;
$$;
