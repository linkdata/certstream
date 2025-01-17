CREATE OR REPLACE PROCEDURE CERTDB_add_new_entry(
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
LANGUAGE plpgsql AS $proc$

DECLARE
  _iss_id INTEGER;
  _sub_id INTEGER;
  _cert_id BIGINT;

BEGIN

	SELECT id FROM CERTDB_ident INTO _iss_id WHERE organization=_iss_org AND province=_iss_prov AND country=_iss_country;
	IF _iss_id IS NULL THEN
		INSERT INTO CERTDB_ident (organization, province, country)
			VALUES (_iss_org, _iss_prov, _iss_country)
			ON CONFLICT (organization, province, country) DO NOTHING RETURNING id INTO _iss_id;
		COMMIT;
		IF _iss_id IS NULL THEN
			SELECT id FROM CERTDB_ident INTO _iss_id WHERE organization=_iss_org AND province=_iss_prov AND country=_iss_country;
		END IF;
	END IF;

	SELECT id FROM CERTDB_ident INTO _sub_id WHERE organization=_sub_org AND province=_sub_prov AND country=_sub_country;
	IF _sub_id IS NULL THEN
		INSERT INTO CERTDB_ident (organization, province, country)
			VALUES (_sub_org, _sub_prov, _sub_country)
			ON CONFLICT (organization, province, country) DO NOTHING RETURNING id INTO _sub_id;
		COMMIT;
		IF _sub_id IS NULL THEN
			SELECT id FROM CERTDB_ident INTO _sub_id WHERE organization=_sub_org AND province=_sub_prov AND country=_sub_country;
		END IF;
	END IF;

	SELECT id FROM CERTDB_cert INTO _cert_id WHERE sha256=_hash;
	IF _cert_id IS NULL THEN
		INSERT INTO CERTDB_cert (notbefore, notafter, commonname, subject, issuer, sha256, precert)
			VALUES (_notbefore, _notafter, _commonname, _sub_id, _iss_id, _hash, _precert)
			ON CONFLICT (sha256) DO NOTHING RETURNING id INTO _cert_id;
		COMMIT;
		IF _cert_id IS NULL THEN
			SELECT id FROM CERTDB_cert INTO _cert_id WHERE sha256=_hash;
		END IF;
	END IF;

    INSERT INTO CERTDB_uri (cert, uri) 
		SELECT _cert_id, UNNEST(STRING_TO_ARRAY(_uris, ' '))
		ON CONFLICT (cert, uri) DO NOTHING;

    INSERT INTO CERTDB_email (cert, email)
		SELECT _cert_id, UNNEST(STRING_TO_ARRAY(_emails, ' '))
		ON CONFLICT (cert, email) DO NOTHING;

	INSERT INTO CERTDB_ipaddress (cert, addr) 
		SELECT _cert_id, inet(UNNEST(STRING_TO_ARRAY(_ipaddrs, ' ')))
		ON CONFLICT (cert, addr) DO NOTHING;

	INSERT INTO CERTDB_dnsname (cert, dnsname) 
		SELECT _cert_id, UNNEST(STRING_TO_ARRAY(_dnsnames, ' '))
		ON CONFLICT (cert, dnsname) DO NOTHING;

	INSERT INTO CERTDB_entry (seen, logindex, cert, stream)
		VALUES (_seen, _logindex, _cert_id, _stream)
		ON CONFLICT DO NOTHING;

	COMMIT;

END
$proc$;
