CREATE OR REPLACE FUNCTION CERTDB_find_since(
  IN _commonname TEXT
)
RETURNS TIMESTAMP
LANGUAGE plpgsql
AS $$
DECLARE _temprow RECORD;
DECLARE _since TIMESTAMP;
DECLARE _subject INTEGER;
DECLARE _issuer INTEGER;
BEGIN
  FOR _temprow IN
	  (SELECT subject, issuer, notbefore, notafter FROM CERTDB_cert
	  WHERE commonname=_commonname
	  ORDER BY notbefore DESC)
  LOOP
    IF _since IS NOT NULL THEN
      IF _subject = _temprow.subject AND _issuer = _temprow.issuer THEN
        IF _temprow.notafter < _since THEN
          EXIT;
        END IF;
    	  _since = _temprow.notbefore;
      END IF;
    ELSE
      _since = _temprow.notbefore;
      _subject = _temprow.subject;
      _issuer = _temprow.issuer;
    END IF;
  END LOOP;
  RETURN _since;
END; $$
