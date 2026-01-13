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
    operator INTEGER NOT NULL REFERENCES CERTDB_operator (id) ON DELETE CASCADE,
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
    since TIMESTAMP NOT NULL,
    commonname TEXT NOT NULL,
    subject INTEGER NOT NULL REFERENCES CERTDB_ident (id),
    issuer INTEGER NOT NULL REFERENCES CERTDB_ident (id),
    sha256 BYTEA NOT NULL,
    precert BOOLEAN NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS CERTDB_cert_sha256_idx ON CERTDB_cert (sha256); -- same hash as crt.sh uses
  CREATE INDEX IF NOT EXISTS CERTDB_cert_notafter_idx ON CERTDB_cert (notafter); -- used when pruning old certs
  CREATE INDEX IF NOT EXISTS CERTDB_cert_commonname_subject_issuer_notbefore_idx -- used when computing 'since'
    ON CERTDB_cert (commonname, subject, issuer, notbefore DESC)
    INCLUDE (since, notafter);
  CREATE INDEX IF NOT EXISTS CERTDB_cert_commonname_empty_idx 
    ON CERTDB_cert (subject, issuer, notbefore DESC) 
    INCLUDE (since, notafter) WHERE commonname = '';
END IF;

IF to_regclass('CERTDB_entry') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_entry (
    seen TIMESTAMP NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC'),
    cert BIGINT NOT NULL, -- do not reference CERTDB_cert since we have no index on this column
    logindex BIGINT NOT NULL,
    stream INTEGER NOT NULL REFERENCES CERTDB_stream (id) ON DELETE CASCADE,
    PRIMARY KEY (stream, logindex)
  );
END IF;

IF to_regclass('CERTDB_domain') IS NULL THEN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE TABLE IF NOT EXISTS CERTDB_domain (
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id) ON DELETE CASCADE,
    wild BOOLEAN NOT NULL,
    www SMALLINT NOT NULL,
    domain TEXT NOT NULL,
    tld TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS CERTDB_domain_cert_idx ON CERTDB_domain (cert);
  CREATE INDEX IF NOT EXISTS CERTDB_domain_domain_idx ON CERTDB_domain USING gin (domain gin_trgm_ops) WITH (fastupdate = off);
END IF;

IF to_regclass('CERTDB_ipaddress') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_ipaddress (
    addr INET NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id) ON DELETE CASCADE,
    PRIMARY KEY (cert, addr)
  );
  CREATE INDEX IF NOT EXISTS CERTDB_ipaddress_addr_idx ON CERTDB_ipaddress (addr);
END IF;

IF to_regclass('CERTDB_email') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_email (
    email TEXT NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id) ON DELETE CASCADE,
    PRIMARY KEY (cert, email)
  );
  CREATE INDEX IF NOT EXISTS CERTDB_email_email_idx ON CERTDB_email (email);
END IF;

IF to_regclass('CERTDB_uri') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_uri (
    uri TEXT NOT NULL,
    cert BIGINT NOT NULL REFERENCES CERTDB_cert (id) ON DELETE CASCADE,
    PRIMARY KEY (cert, uri)
  );
  CREATE INDEX IF NOT EXISTS CERTDB_uri_uri_idx ON CERTDB_uri (uri);
END IF;

IF to_regclass('CERTDB_ingest_log') IS NULL THEN
  CREATE TABLE IF NOT EXISTS CERTDB_ingest_log (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    logged_at TIMESTAMP NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC'),
    statement_name TEXT NOT NULL,
    statement_sql TEXT NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    explain TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS CERTDB_ingest_log_logged_at_idx ON CERTDB_ingest_log (logged_at);
END IF;

CREATE OR REPLACE FUNCTION CERTDB_split_domain(_fqdn text)
RETURNS TABLE(wild boolean, www smallint, domain text, tld text)
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
WITH a AS (
  SELECT string_to_array(_fqdn, '.') AS ary
),
b AS (
  SELECT
    ary,
    COALESCE(array_length(ary, 1), 0) AS len
  FROM a
),
c AS (
  SELECT
    ary,
    len,
    (len > 0 AND ary[1] = '*') AS wild,
    CASE WHEN len > 0 AND ary[1] = '*' THEN 2 ELSE 1 END AS start_pos,
    (len - 2) AS www_limit_pos   -- loop condition: _pos + 1 < _len  => _pos <= _len-2
  FROM b
),
d AS (
  SELECT
    ary,
    len,
    wild,
    start_pos,
    CASE
      WHEN len = 0 OR www_limit_pos < start_pos THEN 0
      ELSE (
        WITH gs AS (
          SELECT i
          FROM generate_series(start_pos, www_limit_pos) AS g(i)
        ),
        first_non AS (
          SELECT min(i) AS i
          FROM gs
          WHERE ary[i] <> 'www'
        )
        SELECT
          CASE
            WHEN (SELECT i FROM first_non) IS NULL THEN (www_limit_pos - start_pos + 1)
            ELSE ((SELECT i FROM first_non) - start_pos)
          END
      )
    END::smallint AS www
  FROM c
)
SELECT
  wild,
  www,
  COALESCE(array_to_string(ary[(start_pos + www) : (len - 1)], '.'), '') AS domain,
  COALESCE(ary[len], '') AS tld
FROM d;
$$;

CREATE OR REPLACE FUNCTION CERTDB_fqdn(
  _wild boolean,
  _www smallint,
  _domain text,
  _tld text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
SELECT array_to_string(
  (CASE WHEN _wild THEN ARRAY['*']::text[] ELSE ARRAY[]::text[] END) ||
  array_fill('www'::text, ARRAY[_www]) ||
  (CASE WHEN _domain <> '' THEN ARRAY[_domain] ELSE ARRAY[]::text[] END) ||
  (CASE WHEN _tld    <> '' THEN ARRAY[_tld]    ELSE ARRAY[]::text[] END),
  '.'
);
$$;

IF to_regclass('CERTDB_dnsnames') IS NULL THEN
  CREATE OR REPLACE VIEW CERTDB_dnsnames AS
  SELECT
    cert,
    CERTDB_fqdn(cd.wild, cd.www, cd.domain, cd.tld) as fqdn,
    cc.notbefore AS notbefore,
    (cd.domain ~ '[^\x00-\x7F]') AS idna,
    (NOW() AT TIME ZONE 'UTC') between cc.notbefore and cc.notafter as valid,
    cc.precert AS precert,
    iss.organization as issuer,
    subj.organization as subject,
    CONCAT('https://crt.sh/?q=', ENCODE(cc.sha256, 'hex'::text)) AS crtsh,
    cd.domain,
    cd.tld
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
