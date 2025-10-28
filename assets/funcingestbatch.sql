CREATE OR REPLACE FUNCTION CERTDB_ingest_batch(_rows jsonb)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  -- Lower commit latency for high-throughput ingest (acceptable risk window)
  PERFORM set_config('synchronous_commit','off', true);
  -- If you keep any GIN elsewhere, this smooths pending-list merges
  PERFORM set_config('gin_pending_list_limit','64MB', true);

  -- 1) Stage payload into a TEMP table (drops at commit)
  CREATE TEMP TABLE tmp_ingest ON COMMIT DROP AS
  SELECT
    (x->>'iss_org')::text      AS iss_org,
    (x->>'iss_prov')::text     AS iss_prov,
    (x->>'iss_country')::text  AS iss_country,
    (x->>'sub_org')::text      AS sub_org,
    (x->>'sub_prov')::text     AS sub_prov,
    (x->>'sub_country')::text  AS sub_country,
    (x->>'commonname')::text   AS commonname,
    (x->>'notbefore')::timestamp without time zone AS notbefore,
    (x->>'notafter') ::timestamp without time zone AS notafter,
    decode(x->>'sha256_hex','hex')::bytea          AS sha256,
    (x->>'precert')::boolean   AS precert,
    (x->>'seen')   ::timestamp without time zone   AS seen,
    (x->>'stream') ::integer    AS stream,
    (x->>'logindex')::bigint    AS logindex,
    coalesce(x->>'dnsnames','') AS dnsnames,
    coalesce(x->>'ipaddrs','')  AS ipaddrs,
    coalesce(x->>'emails','')   AS emails,
    coalesce(x->>'uris','')     AS uris
  FROM jsonb_array_elements(_rows) AS x;

  -- keep only sane rows
  DELETE FROM tmp_ingest
  WHERE sha256 IS NULL OR notbefore IS NULL OR notafter IS NULL;

  -- 2) Ensure idents (issuer & subject), set-wise
  WITH d AS (
    SELECT DISTINCT iss_org AS organization, iss_prov AS province, iss_country AS country
    FROM tmp_ingest
  )
  INSERT INTO CERTDB_ident(organization, province, country)
  SELECT organization, province, country FROM d
  ORDER BY organization, province, country
  ON CONFLICT (organization, province, country) DO NOTHING;

  WITH d AS (
    SELECT DISTINCT sub_org AS organization, sub_prov AS province, sub_country AS country
    FROM tmp_ingest
  )
  INSERT INTO CERTDB_ident(organization, province, country)
  SELECT organization, province, country FROM d
  ORDER BY organization, province, country
  ON CONFLICT (organization, province, country) DO NOTHING;

  -- Map to ident IDs
  ALTER TABLE tmp_ingest ADD COLUMN iss_id integer, ADD COLUMN sub_id integer;
  UPDATE tmp_ingest t
    SET iss_id = i.id
  FROM CERTDB_ident i
  WHERE i.organization=t.iss_org AND i.province=t.iss_prov AND i.country=t.iss_country;

  UPDATE tmp_ingest t
    SET sub_id = i.id
  FROM CERTDB_ident i
  WHERE i.organization=t.sub_org AND i.province=t.sub_prov AND i.country=t.sub_country;

  -- 3) Compute 'since' with overlap rule via index-only LATERAL seek
  CREATE TEMP TABLE tmp_certs ON COMMIT DROP AS
  SELECT
    t.notbefore,
    t.notafter,
    COALESCE(w.since, t.notbefore) AS since,  -- fallback if no overlap
    t.commonname,
    t.sub_id   AS subject,
    t.iss_id   AS issuer,
    t.sha256,
    t.precert
  FROM tmp_ingest t
  LEFT JOIN LATERAL (
    SELECT c.since
    FROM CERTDB_cert c
    WHERE c.subject = t.sub_id
      AND c.issuer = t.iss_id
      AND c.commonname = t.commonname
      AND c.notbefore <  t.notbefore
      AND c.notafter  >= t.notbefore
    ORDER BY c.notbefore DESC
    LIMIT 1
  ) w ON TRUE;

  -- 4) Insert certs (unique on sha256)
  INSERT INTO CERTDB_cert(notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
  SELECT notbefore, notafter, since, commonname, subject, issuer, sha256, precert
  FROM tmp_certs
  ORDER BY sha256
  ON CONFLICT (sha256) DO NOTHING;

  -- 5) Fetch cert IDs back to staging
  ALTER TABLE tmp_ingest ADD COLUMN cert_id bigint;
  UPDATE tmp_ingest t
  SET cert_id = c.id
  FROM CERTDB_cert c
  WHERE c.sha256 = t.sha256;

  -- 6) Entries (idempotent)
  INSERT INTO CERTDB_entry(seen, logindex, cert, stream)
  SELECT seen, logindex, cert_id, stream
  FROM tmp_ingest
  WHERE cert_id IS NOT NULL
  ORDER BY stream, logindex
  ON CONFLICT (stream, logindex) DO NOTHING;

  -- 7) Attach metadata (set-wise, idempotent for uri/email/ip; duplicates allowed for domain)

  -- URIs
  INSERT INTO CERTDB_uri (cert, uri)
  SELECT t.cert_id, unnest(string_to_array(t.uris,' '))
  FROM tmp_ingest t
  WHERE t.uris <> '' AND t.cert_id IS NOT NULL
  ORDER BY t.cert_id, 2
  ON CONFLICT (cert, uri) DO NOTHING;

  -- Emails
  INSERT INTO CERTDB_email (cert, email)
  SELECT t.cert_id, unnest(string_to_array(t.emails,' '))
  FROM tmp_ingest t
  WHERE t.emails <> '' AND t.cert_id IS NOT NULL
  ORDER BY t.cert_id, 2
  ON CONFLICT (cert, email) DO NOTHING;


  -- IPs
  INSERT INTO CERTDB_ipaddress (cert, addr)
  SELECT x.cert_id, inet(x.addr_txt)
  FROM (
    SELECT cert_id, unnest(string_to_array(ipaddrs,' ')) AS addr_txt
    FROM tmp_ingest
    WHERE ipaddrs <> '' AND cert_id IS NOT NULL
  ) x
  ORDER BY x.cert_id, x.addr_txt
  ON CONFLICT (cert, addr) DO NOTHING;

  -- Domains (allow duplicates; DISTINCT trims trivial repeats within the batch)
  INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
  SELECT t.cert_id, (d.s).wild, (d.s).www, (d.s).domain, (d.s).tld
  FROM (
    SELECT DISTINCT cert_id, CERTDB_split_domain(fqdn) AS s
    FROM tmp_ingest
    CROSS JOIN LATERAL unnest(string_to_array(dnsnames,' ')) AS fqdn
    WHERE dnsnames <> '' AND cert_id IS NOT NULL
  ) d
  JOIN tmp_ingest t ON t.cert_id = d.cert_id
  WHERE (d.s).domain <> '' AND (d.s).tld <> '';
END;
$$;
