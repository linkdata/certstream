CREATE OR REPLACE FUNCTION CERTDB_find_since(
  IN _commonname TEXT,
  IN _subject BIGINT,
  IN _issuer BIGINT
)
RETURNS TIMESTAMP
LANGUAGE plpgsql
AS $$
DECLARE _temprow RECORD;
DECLARE _since TIMESTAMP;
BEGIN
  FOR _temprow IN
	  (SELECT notbefore, notafter FROM CERTDB_cert
	  WHERE commonname=_commonname AND subject=_subject AND issuer=_issuer
	  ORDER BY notbefore DESC)
  LOOP
	  IF _since IS NOT NULL AND _temprow.notafter < _since THEN
      EXIT;
    END IF;
	  _since = _temprow.notbefore;
  END LOOP;
  RETURN _since;
END; $$
