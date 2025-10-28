CREATE OR REPLACE PROCEDURE public.certdb_add_new_entry(
    IN _seen timestamp without time zone,
    IN _stream integer,
    IN _logindex bigint,
    IN _precert boolean,
    IN _hash bytea,
    IN _iss_org text, IN _iss_prov text, IN _iss_country text,
    IN _sub_org text, IN _sub_prov text, IN _sub_country text,
    IN _notbefore timestamp without time zone,
    IN _notafter  timestamp without time zone,
    IN _commonname text,
    IN _dnsnames   text,
    IN _ipaddrs    text,
    IN _emails     text,
    IN _uris       text
)
LANGUAGE plpgsql
AS $procedure$
DECLARE
  _iss_id       integer;
  _sub_id       integer;
  _cert_id      bigint;
  _fqdn         text;
  _since        timestamp;
  _sincebefore  timestamp;
BEGIN
    SET LOCAL lock_timeout = '1s';

	SELECT id INTO _iss_id
	FROM certdb_ident
	WHERE organization = _iss_org
		AND province     = _iss_prov
		AND country      = _iss_country;
    IF _iss_id IS NULL THEN
		INSERT INTO certdb_ident (organization, province, country)
		VALUES (_iss_org, _iss_prov, _iss_country)
		ON CONFLICT (organization, province, country) DO NOTHING
		RETURNING id INTO _iss_id;
	    IF _iss_id IS NULL THEN
			SELECT id INTO _iss_id
			FROM certdb_ident
			WHERE organization = _iss_org
				AND province     = _iss_prov
				AND country      = _iss_country;
	    END IF;
    END IF;

	SELECT id INTO _sub_id
	FROM certdb_ident
	WHERE organization = _sub_org
		AND province     = _sub_prov
		AND country      = _sub_country;
    IF _sub_id IS NULL THEN
		INSERT INTO certdb_ident (organization, province, country)
		VALUES (_sub_org, _sub_prov, _sub_country)
		ON CONFLICT (organization, province, country) DO NOTHING
		RETURNING id INTO _sub_id;
		IF _sub_id IS NULL THEN
			SELECT id INTO _sub_id
			FROM certdb_ident
			WHERE organization = _sub_org
			AND province     = _sub_prov
			AND country      = _sub_country;
		END IF;
    END IF;

    /* -------- compute since for this issuer/subject/commonname -------- */
    SELECT since, notbefore
      INTO _since, _sincebefore
    FROM certdb_cert
    WHERE commonname = _commonname
      AND subject    = _sub_id
      AND issuer     = _iss_id
      AND notbefore  < _notbefore
      AND notafter   >= _notbefore
    ORDER BY notbefore DESC
    LIMIT 1;

    IF _since IS NULL THEN
        _since := COALESCE(_sincebefore, _notbefore);
    END IF;

	SELECT id INTO _cert_id
	FROM certdb_cert
	WHERE sha256 = _hash;
	IF _cert_id IS NULL THEN
		INSERT INTO certdb_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
		VALUES (_notbefore, _notafter, _since, _commonname, _sub_id, _iss_id, _hash, _precert)
		ON CONFLICT (sha256) DO NOTHING
		RETURNING id INTO _cert_id;
		IF _cert_id IS NULL THEN
			SELECT id INTO _cert_id
			FROM certdb_cert
			WHERE sha256 = _hash;
		END IF;
	END IF;

    /* -------- fanouts (idempotent) -------- */
    INSERT INTO certdb_uri (cert, uri)
    SELECT _cert_id, UNNEST(STRING_TO_ARRAY(COALESCE(_uris,''), ' '))
    ON CONFLICT (cert, uri) DO NOTHING;

    INSERT INTO certdb_email (cert, email)
    SELECT _cert_id, UNNEST(STRING_TO_ARRAY(COALESCE(_emails,''), ' '))
    ON CONFLICT (cert, email) DO NOTHING;

    INSERT INTO certdb_ipaddress (cert, addr)
    SELECT _cert_id, inet(UNNEST(STRING_TO_ARRAY(COALESCE(_ipaddrs,''), ' ')))
    ON CONFLICT (cert, addr) DO NOTHING;

    FOREACH _fqdn IN ARRAY STRING_TO_ARRAY(COALESCE(_dnsnames,''), ' ')
    LOOP
        INSERT INTO certdb_domain (cert, wild, www, domain, tld)
        SELECT _cert_id, wild, www, domain, tld
        FROM certdb_split_domain(_fqdn);
    END LOOP;

    /* -------- entry (idempotent) -------- */
    INSERT INTO certdb_entry (seen, logindex, cert, stream)
    VALUES (_seen, _logindex, _cert_id, _stream)
    ON CONFLICT (stream, logindex) DO NOTHING;
END
$procedure$;
