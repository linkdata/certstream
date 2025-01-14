CREATE OR REPLACE FUNCTION CERTDB_operator_id(
  IN s_name TEXT,
  IN s_email TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  _id INTEGER;
BEGIN
  SELECT id FROM CERTDB_operator INTO _id WHERE name=s_name AND email=s_email;
  IF NOT FOUND THEN
    INSERT INTO CERTDB_operator (name, email) VALUES (s_name, s_email)
      ON CONFLICT DO NOTHING RETURNING id INTO _id;
  END IF;
  IF NOT FOUND THEN
    SELECT id FROM CERTDB_operator INTO _id WHERE name=s_name AND email=s_email;
  END IF;
  RETURN _id;
END;
$$
;
