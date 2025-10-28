-- DROP FUNCTION CERTDB_ensure_cert(text, text, text, text, text, text, timestamp, timestamp, text, bytea, bool, timestamp, int4, int8);
CREATE OR REPLACE FUNCTION CERTDB_ensure_cert (
    _iss_org text,
    _iss_prov text,
    _iss_country text,
    _sub_org text,
    _sub_prov text,
    _sub_country text,
    _notbefore timestamp WITHOUT time zone,
    _notafter timestamp WITHOUT time zone,
    _commonname text,
    _sha256 bytea,
    _precert boolean,
    _seen timestamp WITHOUT time zone,
    _stream integer,
    _logindex bigint
)
    RETURNS bigint
    LANGUAGE plpgsql
    AS $function$
DECLARE
    _iss_id integer;
    _sub_id integer;
    _cert_id bigint;
    _since timestamp;
    _sincebefore timestamp;
BEGIN
    SELECT id INTO _cert_id
    FROM CERTDB_cert
    WHERE sha256 = _sha256;
    IF _cert_id IS NULL THEN
        SELECT id INTO _iss_id
        FROM CERTDB_ident
        WHERE organization = _iss_org
            AND province = _iss_prov
            AND country = _iss_country;
        IF _iss_id IS NULL THEN
            INSERT INTO CERTDB_ident (organization, province, country)
                VALUES (_iss_org, _iss_prov, _iss_country)
            ON CONFLICT (organization, province, country)
                DO NOTHING
            RETURNING id INTO _iss_id;
            IF _iss_id IS NULL THEN
                SELECT id INTO _iss_id
                FROM CERTDB_ident
                WHERE organization = _iss_org
                    AND province = _iss_prov
                    AND country = _iss_country;
            END IF;
        END IF;
        SELECT id INTO _sub_id
        FROM CERTDB_ident
        WHERE organization = _sub_org
            AND province = _sub_prov
            AND country = _sub_country;
        IF _sub_id IS NULL THEN
            INSERT INTO CERTDB_ident (organization, province, country)
                VALUES (_sub_org, _sub_prov, _sub_country)
            ON CONFLICT (organization, province, country)
                DO NOTHING
            RETURNING id INTO _sub_id;
            IF _sub_id IS NULL THEN
                SELECT id INTO _sub_id
                FROM CERTDB_ident
                WHERE organization = _sub_org
                    AND province = _sub_prov
                    AND country = _sub_country;
            END IF;
        END IF;
        SELECT since, notbefore INTO _since, _sincebefore
        FROM CERTDB_cert
        WHERE commonname = _commonname
            AND subject = _sub_id
            AND issuer = _iss_id
            AND notbefore < _notbefore
            AND notafter >= _notbefore
        ORDER BY notbefore DESC
        LIMIT 1;
        IF _since IS NULL THEN
            _since := COALESCE(_sincebefore, _notbefore);
        END IF;
        INSERT INTO CERTDB_cert (notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
            VALUES (_notbefore, _notafter, _since, _commonname, _sub_id, _iss_id, _sha256, _precert)
        ON CONFLICT (sha256)
            DO NOTHING
        RETURNING id INTO _cert_id;
        IF _cert_id IS NULL THEN
            SELECT id INTO _cert_id
            FROM CERTDB_cert
            WHERE sha256 = _sha256;
        END IF;
    END IF;
    INSERT INTO CERTDB_entry (seen, logindex, cert, stream)
        VALUES (_seen, _logindex, _cert_id, _stream)
    ON CONFLICT (stream, logindex)
        DO NOTHING;
    RETURN _cert_id;
END
$function$;
