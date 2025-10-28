CREATE OR REPLACE FUNCTION CERTDB_ingest_batch(_rows jsonb)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_advisory_lock_id constant bigint := 987654321;
    v_lock_timeout_ms constant integer := 5000;
BEGIN
    -- Critical optimization: async commit
    PERFORM set_config('synchronous_commit', 'off', true);
    PERFORM set_config('work_mem', '256MB', true);
    
    -- Parse input data
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

    -- Add indexes
    CREATE INDEX tmp_ingest_iss_idx ON tmp_ingest(iss_org, iss_prov, iss_country);
    CREATE INDEX tmp_ingest_sub_idx ON tmp_ingest(sub_org, sub_prov, sub_country);
    CREATE INDEX tmp_ingest_sha256_idx ON tmp_ingest(sha256);
    
    -- CRITICAL FIX: Use advisory lock for identity operations only
    PERFORM pg_advisory_lock(v_advisory_lock_id);
    
    -- Insert identities with pre-check to minimize conflicts
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
    
    -- Release advisory lock immediately
    PERFORM pg_advisory_unlock(v_advisory_lock_id);
    
    -- Process certificates with efficient mapping
    CREATE TEMP TABLE tmp_certs_mapped ON COMMIT DROP AS
    WITH mapped AS (
        SELECT 
            t.*,
            iss.id AS iss_id,
            sub.id AS sub_id
        FROM tmp_ingest t
        INNER JOIN CERTDB_ident iss ON (
            iss.organization = t.iss_org 
            AND iss.province = t.iss_prov 
            AND iss.country = t.iss_country
        )
        INNER JOIN CERTDB_ident sub ON (
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
    FROM mapped m
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
    
    -- Insert certificates with RETURNING for efficiency
    CREATE TEMP TABLE cert_ids ON COMMIT DROP AS
    WITH ins AS (
        INSERT INTO CERTDB_cert(notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
        SELECT notbefore, notafter, since, commonname, subject, issuer, sha256, precert
        FROM tmp_certs_mapped
        ON CONFLICT (sha256) DO NOTHING
        RETURNING id, sha256
    )
    SELECT id AS cert_id, sha256 FROM ins
    UNION ALL
    SELECT c.id, c.sha256 
    FROM CERTDB_cert c
    INNER JOIN tmp_certs_mapped t ON c.sha256 = t.sha256
    WHERE NOT EXISTS (SELECT 1 FROM ins WHERE ins.sha256 = c.sha256);
    
    -- Process remaining tables without explicit locks
    INSERT INTO CERTDB_entry(seen, logindex, cert, stream)
    SELECT t.seen, t.logindex, c.cert_id, t.stream
    FROM tmp_certs_mapped t
    INNER JOIN cert_ids c ON c.sha256 = t.sha256
    ON CONFLICT (stream, logindex) DO NOTHING;
    
    -- Process metadata efficiently
    INSERT INTO CERTDB_uri (cert, uri)
    SELECT DISTINCT c.cert_id, trim(unnest(string_to_array(t.uris, ' ')))
    FROM tmp_certs_mapped t
    INNER JOIN cert_ids c ON c.sha256 = t.sha256
    WHERE t.uris <> ''
    ON CONFLICT (cert, uri) DO NOTHING;
    
    INSERT INTO CERTDB_email (cert, email)
    SELECT DISTINCT c.cert_id, trim(unnest(string_to_array(t.emails, ' ')))
    FROM tmp_certs_mapped t
    INNER JOIN cert_ids c ON c.sha256 = t.sha256
    WHERE t.emails <> ''
    ON CONFLICT (cert, email) DO NOTHING;
    
    INSERT INTO CERTDB_ipaddress (cert, addr)
    WITH ip_data AS (
        SELECT DISTINCT 
            c.cert_id, 
            trim(unnest(string_to_array(t.ipaddrs, ' '))) AS addr_txt
        FROM tmp_certs_mapped t
        INNER JOIN cert_ids c ON c.sha256 = t.sha256
        WHERE t.ipaddrs <> ''
    )
    SELECT cert_id, inet(addr_txt)
    FROM ip_data
    WHERE addr_txt <> ''
    ON CONFLICT (cert, addr) DO NOTHING;
    
    INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
    WITH expanded AS (
        SELECT 
            c.cert_id,
            trim(unnest(string_to_array(t.dnsnames, ' '))) AS fqdn
        FROM tmp_certs_mapped t
        INNER JOIN cert_ids c ON c.sha256 = t.sha256
        WHERE t.dnsnames <> ''
    ),
    parsed AS (
        SELECT DISTINCT 
            cert_id,
            (CERTDB_split_domain(fqdn)).*
        FROM expanded
        WHERE fqdn <> ''
    )
    SELECT cert_id, wild, www, domain, tld
    FROM parsed
    WHERE domain <> '' AND tld <> '';
END;
$$;