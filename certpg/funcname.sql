CREATE OR REPLACE FUNCTION CERTDB_name(
  IN _dnsname TEXT
)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
	_a TEXT[];
BEGIN
	_dnsname := lower(_dnsname);
	IF substring(_dnsname for 4) = 'www.' THEN
		_dnsname := substring(_dnsname from 5);
	END IF;
	_a := string_to_array(_dnsname, '.');
	IF array_length(_a, 1) > 0 THEN
		_a := trim_array(_a, 1);
	END IF;
	RETURN array_to_string(_a, '.');
END;
$$
;