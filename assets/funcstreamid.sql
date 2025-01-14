CREATE OR REPLACE FUNCTION CERTDB_stream_id(
  IN s_url TEXT,
  IN s_operator INTEGER,
  IN s_json TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  _id INTEGER;
BEGIN
  SELECT id FROM CERTDB_stream INTO _id WHERE url=s_url;
  IF NOT FOUND THEN
    INSERT INTO CERTDB_stream (url, operator, json) VALUES (s_url, s_operator, s_json)
      ON CONFLICT DO NOTHING RETURNING id INTO _id;
  END IF;
  IF NOT FOUND THEN
    SELECT id FROM CERTDB_stream INTO _id WHERE url=s_url;
  END IF;
  RETURN _id;
END;
$$
;
