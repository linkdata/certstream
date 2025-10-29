CREATE OR REPLACE FUNCTION CERTDB_ingest_batch(_rows jsonb)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  -- Enable asynchronous commit for high-throughput ingest
  PERFORM set_config('synchronous_commit','off', true);
  
  -- Optionally increase work_mem for this session if dealing with large batches
  -- PERFORM set_config('work_mem', '256MB', true);

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

  -- Add indexes to speed up subsequent operations
  -- CREATE INDEX tmp_ingest_iss_idx ON tmp_ingest(iss_org, iss_prov, iss_country);
  -- CREATE INDEX tmp_ingest_sub_idx ON tmp_ingest(sub_org, sub_prov, sub_country);
  -- CREATE INDEX tmp_ingest_sha256_idx ON tmp_ingest(sha256);

  -- 2) Ensure all identities exist (combined issuer and subject in single operation)
  WITH all_idents AS (
      SELECT DISTINCT iss_org AS organization, iss_prov AS province, iss_country AS country
      FROM tmp_ingest
      UNION
      SELECT DISTINCT sub_org AS organization, sub_prov AS province, sub_country AS country
      FROM tmp_ingest
  ),
  new_idents AS (
      SELECT a.* 
      FROM all_idents a
      LEFT JOIN CERTDB_ident i ON (
          i.organization = a.organization 
          AND i.province = a.province 
          AND i.country = a.country
      )
      WHERE i.id IS NULL
  )
  INSERT INTO CERTDB_ident(organization, province, country)
  SELECT organization, province, country 
  FROM new_idents
  ON CONFLICT (organization, province, country) DO NOTHING;

  -- 3) Create temp table with mapped IDs and computed 'since' in one pass
  CREATE TEMP TABLE tmp_certs_with_ids ON COMMIT DROP AS
  WITH mapped_data AS (
    SELECT 
      t.sha256,
      t.notbefore,
      t.notafter,
      t.commonname,
      t.precert,
      t.seen,
      t.stream,
      t.logindex,
      t.dnsnames,
      t.ipaddrs,
      t.emails,
      t.uris,
      iss.id AS iss_id,
      sub.id AS sub_id
    FROM tmp_ingest t
    JOIN CERTDB_ident iss ON (
      iss.organization = t.iss_org 
      AND iss.province = t.iss_prov 
      AND iss.country = t.iss_country
    )
    JOIN CERTDB_ident sub ON (
      sub.organization = t.sub_org 
      AND sub.province = t.sub_prov 
      AND sub.country = t.sub_country
    )
  )
  SELECT
    m.sha256,
    m.notbefore,
    m.notafter,
    COALESCE(overlap.since, m.notbefore) AS since,
    m.commonname,
    m.sub_id AS subject,
    m.iss_id AS issuer,
    m.precert,
    m.seen,
    m.stream,
    m.logindex,
    m.dnsnames,
    m.ipaddrs,
    m.emails,
    m.uris
  FROM mapped_data m
  LEFT JOIN LATERAL (
    SELECT c.since
    FROM CERTDB_cert c
    WHERE c.subject = m.sub_id
      AND c.issuer = m.iss_id
      AND c.commonname = m.commonname
      AND c.notbefore < m.notbefore
      AND c.notafter >= m.notbefore
    ORDER BY c.notbefore DESC
    LIMIT 1
  ) overlap ON TRUE;

  -- Add index for sha256 lookups
  -- CREATE INDEX tmp_certs_sha256_idx ON tmp_certs_with_ids(sha256);

  -- 4) Insert certificates and capture the mapping in one operation
  CREATE TEMP TABLE cert_mapping ON COMMIT DROP AS
  WITH new_certs AS (
    INSERT INTO CERTDB_cert(notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
    SELECT notbefore, notafter, since, commonname, subject, issuer, sha256, precert
    FROM tmp_certs_with_ids
    ORDER BY sha256
    ON CONFLICT (sha256) DO NOTHING
    RETURNING id, sha256
  )
  -- Get both newly inserted and existing cert IDs
  SELECT id AS cert_id, sha256 FROM new_certs
  UNION ALL
  SELECT c.id AS cert_id, c.sha256 
  FROM CERTDB_cert c
  INNER JOIN tmp_certs_with_ids t ON c.sha256 = t.sha256
  WHERE NOT EXISTS (
    SELECT 1 FROM new_certs nc WHERE nc.sha256 = c.sha256
  );

  -- Add index for efficient joins
  -- CREATE INDEX cert_mapping_sha256_idx ON cert_mapping(sha256);

  -- 5) Insert entries using the cert mapping
  INSERT INTO CERTDB_entry(seen, logindex, cert, stream)
  SELECT t.seen, t.logindex, cm.cert_id, t.stream
  FROM tmp_certs_with_ids t
  INNER JOIN cert_mapping cm ON cm.sha256 = t.sha256
  ORDER BY t.stream, t.logindex
  ON CONFLICT (stream, logindex) DO NOTHING;

  -- 6) Process URIs efficiently
  INSERT INTO CERTDB_uri (cert, uri)
  SELECT DISTINCT cm.cert_id, trim(unnest(string_to_array(t.uris, ' ')))
  FROM tmp_certs_with_ids t
  INNER JOIN cert_mapping cm ON cm.sha256 = t.sha256
  WHERE t.uris <> ''
  ORDER BY 1, 2
  ON CONFLICT (cert, uri) DO NOTHING;

  -- 7) Process Emails efficiently
  INSERT INTO CERTDB_email (cert, email)
  SELECT DISTINCT cm.cert_id, trim(unnest(string_to_array(t.emails, ' ')))
  FROM tmp_certs_with_ids t
  INNER JOIN cert_mapping cm ON cm.sha256 = t.sha256
  WHERE t.emails <> ''
  ORDER BY 1, 2
  ON CONFLICT (cert, email) DO NOTHING;

  -- 8) Process IP addresses efficiently
  INSERT INTO CERTDB_ipaddress (cert, addr)
  WITH ip_data AS (
    SELECT DISTINCT 
      cm.cert_id, 
      trim(unnest(string_to_array(t.ipaddrs, ' '))) AS addr_txt
    FROM tmp_certs_with_ids t
    INNER JOIN cert_mapping cm ON cm.sha256 = t.sha256
    WHERE t.ipaddrs <> ''
  )
  SELECT cert_id, inet(addr_txt)
  FROM ip_data
  WHERE addr_txt <> ''  -- Filter out empty strings
  ORDER BY cert_id, addr_txt
  ON CONFLICT (cert, addr) DO NOTHING;

  -- 9) Process domains with optimized string operations
  INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
  WITH expanded_domains AS (
    SELECT 
      cm.cert_id,
      trim(unnest(string_to_array(t.dnsnames, ' '))) AS fqdn
    FROM tmp_certs_with_ids t
    INNER JOIN cert_mapping cm ON cm.sha256 = t.sha256
    WHERE t.dnsnames <> ''
  ),
  parsed_domains AS (
    SELECT DISTINCT 
      cert_id,
      (CERTDB_split_domain(fqdn)).*
    FROM expanded_domains
    WHERE fqdn <> ''  -- Filter out empty strings
  )
  SELECT cert_id, wild, www, domain, tld
  FROM parsed_domains
  WHERE domain <> '' AND tld <> ''
  ORDER BY cert_id;

END;
$$;
