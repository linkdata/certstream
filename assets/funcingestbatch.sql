CREATE OR REPLACE FUNCTION CERTDB_ingest_batch(_rows jsonb)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_batch_size integer;
BEGIN
    PERFORM set_config('synchronous_commit', 'off', true);

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
    
    WITH needed_idents AS (
        SELECT DISTINCT iss_org AS organization, iss_prov AS province, iss_country AS country
        FROM tmp_ingest
        UNION
        SELECT DISTINCT sub_org AS organization, sub_prov AS province, sub_country AS country
        FROM tmp_ingest
    )
    INSERT INTO CERTDB_ident(organization, province, country)
    SELECT n.organization, n.province, n.country 
    FROM needed_idents n
    WHERE NOT EXISTS (
        SELECT 1 FROM CERTDB_ident i 
        WHERE i.organization = n.organization 
          AND i.province = n.province 
          AND i.country = n.country
    )
    ORDER BY organization, province, country
    ON CONFLICT (organization, province, country) DO NOTHING;
    
    WITH mapped_data AS (
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
    ),
    certs_with_since AS (
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
        ) overlap ON TRUE
    ),
    cert_inserts AS (
        INSERT INTO CERTDB_cert(notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
        SELECT notbefore, notafter, since, commonname, subject, issuer, sha256, precert
        FROM certs_with_since
        ORDER BY sha256
        ON CONFLICT (sha256) DO NOTHING
        RETURNING id, sha256
    ),
    all_cert_ids AS (
        SELECT id AS cert_id, sha256 FROM cert_inserts
        UNION ALL
        SELECT c.id, c.sha256 
        FROM CERTDB_cert c
        INNER JOIN certs_with_since cs ON c.sha256 = cs.sha256
        WHERE NOT EXISTS (SELECT 1 FROM cert_inserts ci WHERE ci.sha256 = c.sha256)
    ),
    entry_inserts AS (
        INSERT INTO CERTDB_entry(seen, logindex, cert, stream)
        SELECT cs.seen, cs.logindex, ac.cert_id, cs.stream
        FROM certs_with_since cs
        INNER JOIN all_cert_ids ac ON ac.sha256 = cs.sha256
        ORDER BY stream, logindex
        ON CONFLICT (stream, logindex) DO NOTHING
        RETURNING cert
    )
    SELECT COUNT(*) INTO v_batch_size FROM all_cert_ids;  -- Just to complete the CTE
    
    WITH cert_mapping AS (
        SELECT DISTINCT c.id AS cert_id, t.sha256, t.uris, t.emails, t.ipaddrs, t.dnsnames
        FROM tmp_ingest t
        INNER JOIN CERTDB_cert c ON c.sha256 = t.sha256
    )
    INSERT INTO CERTDB_uri (cert, uri)
    SELECT DISTINCT cm.cert_id, trim(u.uri)
    FROM cert_mapping cm
    CROSS JOIN LATERAL unnest(string_to_array(cm.uris, ' ')) AS u(uri)
    WHERE cm.uris <> '' AND trim(u.uri) <> ''
    ORDER BY cm.cert_id, 2
    ON CONFLICT (cert, uri) DO NOTHING;
    
    WITH cert_mapping AS (
        SELECT DISTINCT c.id AS cert_id, t.sha256, t.emails
        FROM tmp_ingest t
        INNER JOIN CERTDB_cert c ON c.sha256 = t.sha256
    )
    INSERT INTO CERTDB_email (cert, email)
    SELECT DISTINCT cm.cert_id, trim(e.email)
    FROM cert_mapping cm
    CROSS JOIN LATERAL unnest(string_to_array(cm.emails, ' ')) AS e(email)
    WHERE cm.emails <> '' AND trim(e.email) <> ''
    ORDER BY cm.cert_id, 2
    ON CONFLICT (cert, email) DO NOTHING;
    
    WITH cert_mapping AS (
        SELECT DISTINCT c.id AS cert_id, t.sha256, t.ipaddrs
        FROM tmp_ingest t
        INNER JOIN CERTDB_cert c ON c.sha256 = t.sha256
    ),
    ip_data AS (
        SELECT DISTINCT cm.cert_id, trim(ip.addr) AS addr_txt
        FROM cert_mapping cm
        CROSS JOIN LATERAL unnest(string_to_array(cm.ipaddrs, ' ')) AS ip(addr)
        WHERE cm.ipaddrs <> '' AND trim(ip.addr) <> ''
    )
    INSERT INTO CERTDB_ipaddress (cert, addr)
    SELECT cert_id, inet(addr_txt)
    FROM ip_data
    ORDER BY cert_id, 2
    ON CONFLICT (cert, addr) DO NOTHING;
    
    WITH cert_mapping AS (
        SELECT DISTINCT c.id AS cert_id, t.sha256, t.dnsnames
        FROM tmp_ingest t
        INNER JOIN CERTDB_cert c ON c.sha256 = t.sha256
    ),
    expanded AS (
        SELECT cm.cert_id, trim(d.fqdn) AS fqdn
        FROM cert_mapping cm
        CROSS JOIN LATERAL unnest(string_to_array(cm.dnsnames, ' ')) AS d(fqdn)
        WHERE cm.dnsnames <> '' AND trim(d.fqdn) <> ''
    ),
    parsed AS (
        SELECT DISTINCT cert_id, (CERTDB_split_domain(fqdn)).*
        FROM expanded
    )
    INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
    SELECT cert_id, wild, www, domain, tld
    FROM parsed
    WHERE domain <> '' AND tld <> '';

END;
$$;
