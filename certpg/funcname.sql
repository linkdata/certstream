CREATE OR REPLACE FUNCTION CERTDB_name(
  IN _dnsname TEXT
)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
	RETURN array_to_string(array_remove(trim_array(string_to_array(lower(_dnsname),'.'),1),'www'),'.');
END;
$$
;