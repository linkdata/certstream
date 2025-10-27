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
AS $$
DECLARE
  _iss_id       integer;
  _sub_id       integer;
  _cert_id      bigint;
  _fqdn         text;
  _since        timestamp;
  _sincebefore  timestamp;
BEGIN
    -- Optional per-call guard (keeps waits bounded; adjust as you like)
    SET LOCAL lock_timeout = '1s';

    /* -------- issuer ident: insert-or-select (no row lock on conflict) -------- */
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

    /* -------- subject ident: insert-or-select -------- */
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
        _since := coalesce(_sincebefore, _notbefore);
    END IF;

    /* -------- cert: insert-or-select (no row lock on conflict) -------- */
    INSERT INTO certdb_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
    VALUES (_notbefore, _notafter, _since, _commonname, _sub_id, _iss_id, _hash, _precert)
    ON CONFLICT (sha256) DO NOTHING
    RETURNING id INTO _cert_id;

    IF _cert_id IS NULL THEN
        SELECT id INTO _cert_id
        FROM certdb_cert
        WHERE sha256 = _hash;
    END IF;

    /* -------- fanouts (idempotent) -------- */
    INSERT INTO certdb_uri (cert, uri)
    SELECT _cert_id, unnest(string_to_array(coalesce(_uris,''), ' '))
    ON CONFLICT (cert, uri) DO NOTHING;

    INSERT INTO certdb_email (cert, email)
    SELECT _cert_id, unnest(string_to_array(coalesce(_emails,''), ' '))
    ON CONFLICT (cert, email) DO NOTHING;

    INSERT INTO certdb_ipaddress (cert, addr)
    SELECT _cert_id, inet(unnest(string_to_array(coalesce(_ipaddrs,''), ' ')))
    ON CONFLICT (cert, addr) DO NOTHING;

    FOREACH _fqdn IN ARRAY string_to_array(coalesce(_dnsnames,''), ' ')
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
$$;
