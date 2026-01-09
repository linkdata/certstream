CREATE OR REPLACE FUNCTION CERTDB_stream_id(
  s_url      text,
  s_operator integer,
  s_json     text
)
RETURNS integer
LANGUAGE sql
AS $$
WITH existing AS (
  SELECT id
  FROM CERTDB_stream
  WHERE url = $1
),
upsert AS (
  INSERT INTO CERTDB_stream (url, operator, json)
  SELECT $1, $2, $3
  WHERE NOT EXISTS (SELECT 1 FROM existing)
  ON CONFLICT (url) DO UPDATE
    SET url = EXCLUDED.url
  RETURNING id
)
SELECT id FROM upsert
UNION ALL
SELECT id FROM existing
LIMIT 1;
$$;