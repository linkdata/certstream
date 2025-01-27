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
INSERT INTO certdb_domain
  SELECT wild, www, domain, tld, cert
  FROM certdb_dnsname, CERTDB_split_domain(certdb_dnsname.dnsname) AS (wild BOOL, www SMALLINT, domain TEXT, tld TEXT);
*/
IF to_regclass('CERTDB_domain') IS NULL THEN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE TABLE IF NOT EXISTS CERTDB_domain (
    wild BOOLEAN NOT NULL,
    www SMALLINT NOT NULL,
    domain TEXT NOT NULL,
    tld TEXT NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
    PRIMARY KEY (cert, wild, www, domain, tld)
  );
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

IF NOT EXISTS(SELECT * FROM pg_proc WHERE proname = 'CERTDB_split_domain') THEN
  CREATE OR REPLACE FUNCTION CERTDB_split_domain(_fqdn TEXT)
  RETURNS RECORD
  LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
  AS $split_fn$
  DECLARE
	  _wild BOOL;
	  _www SMALLINT;
	  _domain TEXT;
    _tld TEXT;
    _ret RECORD;
  BEGIN
	  _wild := _fqdn ~ '^\*\.';
	  _www := ((regexp_instr(_fqdn, '^(?:\*\.)?(www\.)+',1,1,1)-1)/4)::smallint;
	  _domain := array_to_string(regexp_match(_fqdn, '(?:^(?:\*\.)?(?:www\.)*)?(.*)\..*'),'');
	  _tld := array_to_string(regexp_match(_fqdn, '(?:.*)\.([^.]+)'),'');
    IF _domain IS NULL THEN
      _domain := _fqdn;
	  END IF;
	  IF _tld IS NULL THEN
		  _tld := '';
    END IF;
    _ret := (_wild, _www, _domain, _tld);
    RETURN _ret;
  END;
  $split_fn$
  ;
END IF;

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
