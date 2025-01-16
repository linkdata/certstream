CREATE OR REPLACE FUNCTION CERTDB_new_entry(
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
RETURNS BIGINT
LANGUAGE sql
BEGIN ATOMIC;
	WITH
    _ensure_subject AS (
      INSERT INTO CERTDB_ident (organization, province, country)
      SELECT _sub_org, _sub_prov, _sub_country
      WHERE NOT EXISTS (
        SELECT id FROM CERTDB_ident WHERE organization=_sub_org AND province=_sub_prov AND country=_sub_country
      )
      RETURNING *
    ),
	  _subject AS (
      (
        SELECT id FROM CERTDB_ident WHERE organization=_sub_org AND province=_sub_prov AND country=_sub_country
        UNION ALL
        SELECT id FROM _ensure_subject
      ) LIMIT 1
	  ),
    _ensure_issuer AS (
      INSERT INTO CERTDB_ident (organization, province, country)
      SELECT _iss_org, _iss_prov, _iss_country
      WHERE NOT EXISTS (
        SELECT id FROM CERTDB_ident WHERE organization=_iss_org AND province=_iss_prov AND country=_iss_country
      )
      RETURNING *
    ),
	  _issuer AS (
      (
        SELECT id FROM CERTDB_ident WHERE organization=_iss_org AND province=_iss_prov AND country=_iss_country
        UNION ALL
        SELECT id FROM _ensure_issuer
      ) LIMIT 1
	  ),
    _ensure_cert AS (
      INSERT INTO CERTDB_cert (notbefore, notafter, commonname, subject, issuer, sha256, precert)
      SELECT _notbefore, _notafter, _commonname, (SELECT id FROM _subject), (SELECT id FROM _issuer), _hash, _precert
      WHERE NOT EXISTS (
        SELECT id FROM CERTDB_cert WHERE sha256=_hash
      )
      RETURNING *
    ),
    _cert_id AS (
      (
        SELECT id FROM CERTDB_cert WHERE sha256=_hash
        UNION ALL
        SELECT id FROM _ensure_cert
      ) LIMIT 1
    ),
    _add_dnsnames AS (
      INSERT INTO CERTDB_dnsname (cert, dnsname)
      SELECT id, UNNEST(STRING_TO_ARRAY(_dnsnames, ' '))
      FROM _cert_id ON CONFLICT (cert, dnsname) DO NOTHING
    ),
    _add_emails AS (
      INSERT INTO CERTDB_email (cert, email) 
      SELECT id, UNNEST(STRING_TO_ARRAY(_emails, ' ')) 
      FROM _cert_id ON CONFLICT (cert, email) DO NOTHING
    ),
    _add_uris AS (
      INSERT INTO CERTDB_uri (cert, uri)
      SELECT id, UNNEST(STRING_TO_ARRAY(_uris, ' '))
      FROM _cert_id ON CONFLICT (cert, uri) DO NOTHING
    ),
    _add_ipaddrs AS (
      INSERT INTO CERTDB_ipaddress (cert, addr)
      SELECT id, inet(UNNEST(STRING_TO_ARRAY(_ipaddrs, ' ')))
      FROM _cert_id ON CONFLICT (cert, addr) DO NOTHING
    )
    SELECT id FROM _cert_id;
END;
