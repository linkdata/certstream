CREATE OR REPLACE FUNCTION CERTDB_name(
  IN _dnsname TEXT
)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    _result TEXT := LOWER(_dnsname);
BEGIN
    _result := REPLACE(_result, '.com', 'A');
    _result := REPLACE(_result, '.net', 'B');
    _result := REPLACE(_result, '.org', 'C');
    _result := REPLACE(_result, '.dev', 'D');
    _result := REPLACE(_result, '.at', 'E');
    _result := REPLACE(_result, '.au', 'F');
    _result := REPLACE(_result, '.be', 'G');
    _result := REPLACE(_result, '.br', 'H');
    _result := REPLACE(_result, '.ca', 'I');
    _result := REPLACE(_result, '.ch', 'J');
    _result := REPLACE(_result, '.cn', 'K');
    _result := REPLACE(_result, '.de', 'L');
    _result := REPLACE(_result, '.dk', 'M');
    _result := REPLACE(_result, '.es', 'N');
    _result := REPLACE(_result, '.eu', 'O');
    _result := REPLACE(_result, '.fr', 'P');
    _result := REPLACE(_result, '.in', 'Q');
    _result := REPLACE(_result, '.it', 'R');
    _result := REPLACE(_result, '.jp', 'S');
    _result := REPLACE(_result, '.no', 'T');
    _result := REPLACE(_result, '.ru', 'U');
    _result := REPLACE(_result, '.se', 'V');
    _result := REPLACE(_result, '.su', 'W');
    _result := REPLACE(_result, '.uk', 'X');
    _result := REPLACE(_result, 'web', 'Y');
    _result := REPLACE(_result, 'www', 'Z');
    RETURN _result;
END;
$$
;
