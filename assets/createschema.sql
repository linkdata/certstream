DO $outer$
BEGIN

IF to_regclass('CERTDB_operator') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_operator (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name TEXT NOT NULL,
    email TEXT NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS CERTDB_operator_full_idx ON CERTDB_operator (name, email);
END IF;

IF to_regclass('CERTDB_stream') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_stream (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    url TEXT NOT NULL UNIQUE,
    operator INTEGER NOT NULL REFERENCES CERTDB_operator (id),
    json TEXT NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS CERTDB_stream_url_idx ON CERTDB_stream (url);
END IF;

IF to_regclass('CERTDB_ident') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_ident (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    organization TEXT NOT NULL,
    province TEXT NOT NULL,
    country TEXT NOT NULL
  );
  INSERT INTO CERTDB_ident (organization, province, country) VALUES ('', '', '') ON CONFLICT DO NOTHING;
  CREATE UNIQUE INDEX IF NOT EXISTS CERTDB_ident_full_idx ON CERTDB_ident (organization, province, country);
END IF;

IF to_regclass('CERTDB_cert') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_cert (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    notbefore TIMESTAMP NOT NULL,
    notafter TIMESTAMP NOT NULL,
    commonname TEXT NOT NULL,
    subject INTEGER NOT NULL REFERENCES CERTDB_ident (id),
    issuer INTEGER NOT NULL REFERENCES CERTDB_ident (id),
    sha256 BYTEA NOT NULL,
    precert BOOLEAN NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS CERTDB_cert_sha256_idx ON CERTDB_cert (sha256);
END IF;

IF to_regclass('CERTDB_entry') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_entry (
    seen TIMESTAMP NOT NULL DEFAULT NOW(),
    logindex BIGINT NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
    stream INTEGER NOT NULL REFERENCES CERTDB_stream (id),
    PRIMARY KEY (stream, logindex)
  );
  CREATE INDEX IF NOT EXISTS CERTDB_entry_seen_idx ON CERTDB_entry (seen);
END IF;

/*
  INSERT INTO certdb_domain (cert, wild, www, domain, tld)
  SELECT cert, wild, www, domain, tld FROM certdb_dnsname, CERTDB_split_domain(certdb_dnsname.dnsname);
*/
IF to_regclass('CERTDB_domain') IS NULL THEN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE TABLE IF NOT EXISTS CERTDB_domain (
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
    wild BOOLEAN NOT NULL,
    www SMALLINT NOT NULL,
    domain TEXT NOT NULL,
    tld TEXT NOT NULL
  );
  CREATE INDEX CERTDB_domain_cert_idx ON CERTDB_domain (cert);
  CREATE INDEX CERTDB_domain_domain_idx ON CERTDB_domain USING gin (domain gin_trgm_ops);
END IF;

IF to_regclass('CERTDB_ipaddress') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_ipaddress (
    addr INET NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
    PRIMARY KEY (cert, addr)
  );
  CREATE INDEX IF NOT EXISTS CERTDB_ipaddress_addr_idx ON CERTDB_ipaddress (addr);
END IF;

IF to_regclass('CERTDB_email') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_email (
    email TEXT NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
    PRIMARY KEY (cert, email)
  );
  CREATE INDEX IF NOT EXISTS CERTDB_email_email_idx ON CERTDB_email (email);
END IF;

IF to_regclass('CERTDB_uri') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_uri (
    uri TEXT NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
    PRIMARY KEY (cert, uri)
  );
  CREATE INDEX IF NOT EXISTS CERTDB_uri_uri_idx ON CERTDB_uri (uri);
END IF;

IF NOT EXISTS(SELECT * FROM pg_proc WHERE proname = 'CERTDB_fqdn') THEN
  CREATE OR REPLACE FUNCTION CERTDB_fqdn(
    _wild BOOLEAN,
    _www SMALLINT,
    _domain TEXT,
    _tld TEXT
  )
  RETURNS TEXT
  LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
  AS $fqdn_fn$
  DECLARE
    _fqdn TEXT NOT NULL DEFAULT '';
  BEGIN
    IF _wild THEN
      _fqdn := '*.';
    END IF;
    _fqdn := _fqdn || repeat('www.', _www) ||  _domain || '.' || _tld;
    RETURN _fqdn;
  END;
  $fqdn_fn$
  ;
END IF;

CREATE OR REPLACE FUNCTION CERTDB_split_domain(_fqdn TEXT)
  RETURNS TABLE(wild BOOL, www SMALLINT, domain TEXT, tld TEXT)
  LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS
$split_fn$
DECLARE
  _wild BOOL NOT NULL DEFAULT FALSE;
  _www SMALLINT NOT NULL DEFAULT 0;
  _domain TEXT NOT NULL DEFAULT '';
  _tld TEXT NOT NULL DEFAULT '';
  _pos INTEGER NOT NULL DEFAULT 1;
  _ary TEXT[];
  _len INTEGER;
BEGIN
  _ary := STRING_TO_ARRAY(_fqdn, '.');
  _len := ARRAY_LENGTH(_ary, 1);
  IF _len > 0 THEN
    IF _ary[_pos] = '*' THEN
      _wild := TRUE;
      _pos := _pos + 1;
    END IF;
    WHILE _pos + 1 < _len AND _ary[_pos] = 'www' LOOP
      _www := _www + 1;
      _pos := _pos + 1;
    END LOOP;
    IF _pos < _len OR _pos > 1 AND _pos <= _len THEN
      _tld := _ary[_len];
      _len := _len - 1;
    END IF;
    _domain := ARRAY_TO_STRING(_ary[_pos:_len], '.');
  END IF;
  RETURN QUERY SELECT _wild, _www, _domain, _tld;
END;
$split_fn$;

IF to_regclass('CERTDB_dnsnames') IS NULL THEN
  CREATE OR REPLACE VIEW CERTDB_dnsnames AS
  SELECT
    cert,
    CERTDB_fqdn(cd.wild, cd.www, cd.domain, cd.tld),
    cc.notbefore AS notbefore,
    cd.domain !~ '^[[:ascii:]]+$'::text AS idna,
    NOW() between cc.notbefore and cc.notafter as valid,
    cc.precert AS precert,
    iss.organization as issuer,
    subj.organization as subject,
    CONCAT('https://crt.sh/?q=', ENCODE(cc.sha256, 'hex'::text)) AS crtsh
  FROM CERTDB_domain cd
  INNER JOIN CERTDB_cert cc on cc.id = cd.cert 
  INNER JOIN CERTDB_ident subj on subj.id = cc.subject
  INNER JOIN CERTDB_ident iss on iss.id = cc.issuer
  ;
END IF;

IF to_regclass('CERTDB_entries') IS NULL THEN
  CREATE OR REPLACE VIEW CERTDB_entries AS
  SELECT
    ce.seen,
    strm.url AS url,
    ce.stream,
    ce.logindex,
    ce.cert,
    CONCAT('https://crt.sh/?q=', ENCODE((SELECT sha256 FROM CERTDB_cert WHERE id = ce.cert), 'hex'::text)) AS crtsh
  FROM CERTDB_entry ce
  INNER JOIN CERTDB_stream strm on strm.id = ce.stream
  ;
END IF;

END
$outer$;
