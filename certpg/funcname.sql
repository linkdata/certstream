CREATE OR REPLACE FUNCTION CERTDB_name(
  IN _dnsname TEXT
)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    _result TEXT := LOWER(_dnsname);
	_tld TEXT;
	_len INT;
BEGIN
	_len := length(_result);
	IF _len > 3 AND substring(_result from _len-3 for 1) = '.' THEN
		_tld := substring(_result from _len-3);
		IF array_position(ARRAY['.com', '.net', '.org', '.dev'], _tld) IS NOT NULL THEN
			_result := substring(_result for _len-4);
		END IF;
	END IF;
	_result := LTRIM(_result, 'w.');
    RETURN _result;
END;
$$
;
