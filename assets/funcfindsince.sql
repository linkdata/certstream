CREATE OR REPLACE FUNCTION CERTDB_find_since(
  IN _commonname TEXT,
  IN _subject INTEGER,
  IN _issuer INTEGER,
  IN _notbefore TIMESTAMP
)
RETURNS TIMESTAMP
LANGUAGE plpgsql
AS $$
DECLARE _temprow RECORD;
DECLARE _since TIMESTAMP;
BEGIN
  IF _commonname='' THEN
    RETURN _notbefore;
  END IF;
  FOR _temprow IN
	  (SELECT DISTINCT notbefore, notafter FROM CERTDB_cert
	  WHERE commonname=_commonname AND subject=_subject AND issuer=_issuer AND notbefore <= _notbefore
	  ORDER BY notbefore DESC LIMIT 365)
  LOOP
    IF _since IS NOT NULL AND _temprow.notafter < _since THEN
      EXIT;
    END IF;
    _since = _temprow.notbefore;
  END LOOP;
  RETURN _since;
END; $$
