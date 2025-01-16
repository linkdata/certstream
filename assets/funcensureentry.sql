CREATE OR REPLACE FUNCTION CERTDB_ensure_entry(
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
  _commonname TEXT
)
RETURNS BIGINT
LANGUAGE sql
BEGIN ATOMIC;
  WITH neworexisting AS (
    INSERT INTO CERTDB_entry (seen, logindex, cert, stream)
      VALUES (
        _seen,
        _logindex,
        CERTDB_ensure_cert(
          _notbefore, _notafter, _commonname,
          CERTDB_ensure_ident(_sub_org, _sub_prov, _sub_country),
          CERTDB_ensure_ident(_iss_org, _iss_prov, _iss_country),
          _hash, _precert
          ),
        _stream
      )
      ON CONFLICT (stream, logindex) DO UPDATE SET seen=_seen
      RETURNING cert
  ) SELECT cert FROM neworexisting;
END;