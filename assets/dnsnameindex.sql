DO $outer$
BEGIN

IF NOT EXISTS(SELECT * FROM pg_proc WHERE proname = 'CERTDB_name') THEN
  CREATE FUNCTION CERTDB_name(
    IN _dnsname TEXT
  )
  RETURNS TEXT LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $name_fn$
  DECLARE
    _a TEXT[];
  BEGIN
    _dnsname := lower(_dnsname);
    IF substring(_dnsname for 4) = 'www.' THEN
      _dnsname := substring(_dnsname from 4);
    END IF;
    _a := string_to_array(_dnsname, '.');
    IF array_length(_a, 1) > 0 THEN
      _a := trim_array(_a, 1);
      _dnsname := array_to_string(_a, '.') || '.';
    END IF;
    RETURN _dnsname;
  END;
  $name_fn$
  ;
END IF;

IF to_regclass('CERTDB_dnsname_name_idx') IS NULL THEN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE INDEX CONCURRENTLY CERTDB_dnsname_name_idx 
    ON CERTDB_dnsname USING GIN (CERTDB_name(dnsname) gin_trgm_ops);
END IF;

END
$outer$;
