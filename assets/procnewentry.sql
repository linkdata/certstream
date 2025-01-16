CREATE OR REPLACE PROCEDURE CERTDB_new_entry(
  _seen TIMESTAMP,
  _stream INTEGER, 
  _logindex BIGINT, 
  _precert BOOLEAN,
  _hash BYTEA, 
  _iss_org TEXT, 
  _iss_prov TEXT, 
  _iss_country TEXT, 
  _sub_org TEXT, 
  _sub_prov TEXT, 
  _sub_country TEXT, 
  _notbefore TIMESTAMP,
  _notafter TIMESTAMP,
  _commonname TEXT,
  _dnsnames TEXT,
  _ipaddrs TEXT,
  _emails TEXT,
  _uris TEXT
)
LANGUAGE sql
BEGIN ATOMIC;
  SELECT CERTDB_fill_entry(
    CERTDB_ensure_entry(
      _seen,
      _stream, 
      _logindex, 
      _precert,
      _hash, 
      _iss_org, 
      _iss_prov, 
      _iss_country, 
      _sub_org, 
      _sub_prov, 
      _sub_country, 
      _notbefore,
      _notafter,
      _commonname
    ),
  _dnsnames,
  _ipaddrs,
  _emails,
  _uris
  );
END;
