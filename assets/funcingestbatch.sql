CREATE OR REPLACE FUNCTION CERTDB_ingest_exec(
    _debug boolean,
    _statement_name text,
    _statement_sql text,
    _arg jsonb DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    plan_line text;
    plan_text text := '';
    started_at timestamptz;
    finished_at timestamptz;
BEGIN
    IF _debug THEN
        IF _arg IS NULL THEN
            FOR plan_line IN EXECUTE format('EXPLAIN (FORMAT TEXT) %s', _statement_sql) LOOP
                IF plan_text = '' THEN
                    plan_text = plan_line;
                ELSE
                    plan_text = plan_text || E'\n' || plan_line;
                END IF;
            END LOOP;
        ELSE
            FOR plan_line IN EXECUTE format('EXPLAIN (FORMAT TEXT) %s', _statement_sql) USING _arg LOOP
                IF plan_text = '' THEN
                    plan_text = plan_line;
                ELSE
                    plan_text = plan_text || E'\n' || plan_line;
                END IF;
            END LOOP;
        END IF;
    END IF;

    started_at = clock_timestamp();
    IF _arg IS NULL THEN
        EXECUTE _statement_sql;
    ELSE
        EXECUTE _statement_sql USING _arg;
    END IF;
    finished_at = clock_timestamp();

    IF _debug THEN
        INSERT INTO CERTDB_ingest_log (
            logged_at,
            statement_name,
            statement_sql,
            duration_ms,
            explain
        )
        VALUES (
            finished_at AT TIME ZONE 'UTC',
            _statement_name,
            _statement_sql,
            EXTRACT(EPOCH FROM (finished_at - started_at)) * 1000,
            plan_text
        );
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION CERTDB_ingest_batch(_rows jsonb)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    debug_enabled boolean;
    tmp_ingest_sql text := $sql$
CREATE TEMP TABLE tmp_ingest ON COMMIT DROP AS
SELECT
    x.iss_org AS iss_org,
    x.iss_prov AS iss_prov,
    x.iss_country AS iss_country,
    x.sub_org AS sub_org,
    x.sub_prov AS sub_prov,
    x.sub_country AS sub_country,
    x.commonname AS commonname,
    x.notbefore AT TIME ZONE 'UTC' AS notbefore,
    x.notafter AT TIME ZONE 'UTC' AS notafter,
    decode(x.sha256_hex, 'hex')::bytea AS sha256,
    x.precert AS precert,
    x.seen AT TIME ZONE 'UTC' AS seen,
    x.stream AS stream,
    x.logindex AS logindex,
    coalesce(x.dnsnames, '') AS dnsnames,
    coalesce(x.ipaddrs, '') AS ipaddrs,
    coalesce(x.emails, '') AS emails,
    coalesce(x.uris, '') AS uris
FROM jsonb_to_recordset($1) AS x(
    iss_org text,
    iss_prov text,
    iss_country text,
    sub_org text,
    sub_prov text,
    sub_country text,
    commonname text,
    notbefore timestamptz,
    notafter timestamptz,
    sha256_hex text,
    precert boolean,
    seen timestamptz,
    stream integer,
    logindex bigint,
    dnsnames text,
    ipaddrs text,
    emails text,
    uris text
)
$sql$;
    ident_insert_sql text := $sql$
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
ON CONFLICT (organization, province, country) DO NOTHING
$sql$;
    tmp_new_certs_sql text := $sql$
CREATE TEMP TABLE tmp_new_certs ON COMMIT DROP AS
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
unique_certs AS (
    SELECT DISTINCT ON (sha256)
        sha256,
        notbefore,
        notafter,
        commonname,
        sub_id AS subject,
        iss_id AS issuer,
        precert,
        dnsnames,
        ipaddrs,
        emails,
        uris
    FROM mapped_data
    ORDER BY sha256
),
new_certs AS (
    SELECT u.*
    FROM unique_certs u
    WHERE NOT EXISTS (
        SELECT 1
        FROM CERTDB_cert c
        WHERE c.sha256 = u.sha256
    )
),
certs_with_since AS (
    SELECT
        u.sha256,
        u.notbefore,
        u.notafter,
        COALESCE(overlap.since, u.notbefore) AS since,
        u.commonname,
        u.subject,
        u.issuer,
        u.precert
    FROM new_certs u
    LEFT JOIN LATERAL (
        SELECT c.since
        FROM CERTDB_cert c
        WHERE c.subject = u.subject
          AND c.issuer = u.issuer
          AND c.commonname = u.commonname
          AND c.notbefore < u.notbefore
          AND c.notafter >= u.notbefore
        ORDER BY c.notbefore DESC
        LIMIT 1
    ) overlap ON TRUE
),
cert_inserts AS (
    INSERT INTO CERTDB_cert(notbefore, notafter, since, commonname, subject, issuer, sha256, precert)
    SELECT notbefore, notafter, since, commonname, subject, issuer, sha256, precert
    FROM certs_with_since
    ON CONFLICT (sha256) DO NOTHING
    RETURNING id, sha256
),
all_cert_ids AS (
    SELECT ci.id AS cert_id, ci.sha256
    FROM cert_inserts ci
    UNION
    SELECT c.id, c.sha256
    FROM CERTDB_cert c
    INNER JOIN (
        SELECT DISTINCT sha256
        FROM mapped_data
    ) md ON c.sha256 = md.sha256
),
entry_inserts AS (
    INSERT INTO CERTDB_entry(seen, logindex, cert, stream)
    SELECT md.seen, md.logindex, ac.cert_id, md.stream
    FROM mapped_data md
    INNER JOIN all_cert_ids ac ON ac.sha256 = md.sha256
    ON CONFLICT (stream, logindex) DO NOTHING
    RETURNING cert
)
SELECT ci.id AS cert_id, uc.sha256, uc.uris, uc.emails, uc.ipaddrs, uc.dnsnames
FROM cert_inserts ci
INNER JOIN unique_certs uc ON uc.sha256 = ci.sha256
$sql$;
    insert_uri_sql text := $sql$
INSERT INTO CERTDB_uri (cert, uri)
SELECT DISTINCT tnc.cert_id, trim(u.uri)
FROM tmp_new_certs tnc
CROSS JOIN LATERAL unnest(string_to_array(tnc.uris, ' ')) AS u(uri)
WHERE tnc.uris <> '' AND trim(u.uri) <> ''
ON CONFLICT (cert, uri) DO NOTHING
$sql$;
    insert_email_sql text := $sql$
INSERT INTO CERTDB_email (cert, email)
SELECT DISTINCT tnc.cert_id, trim(e.email)
FROM tmp_new_certs tnc
CROSS JOIN LATERAL unnest(string_to_array(tnc.emails, ' ')) AS e(email)
WHERE tnc.emails <> '' AND trim(e.email) <> ''
ON CONFLICT (cert, email) DO NOTHING
$sql$;
    insert_ip_sql text := $sql$
WITH ip_data AS (
    SELECT DISTINCT tnc.cert_id, trim(ip.addr) AS addr_txt
    FROM tmp_new_certs tnc
    CROSS JOIN LATERAL unnest(string_to_array(tnc.ipaddrs, ' ')) AS ip(addr)
    WHERE tnc.ipaddrs <> '' AND trim(ip.addr) <> ''
)
INSERT INTO CERTDB_ipaddress (cert, addr)
SELECT cert_id, inet(addr_txt)
FROM ip_data
ON CONFLICT (cert, addr) DO NOTHING
$sql$;
    insert_domain_sql text := $sql$
WITH expanded AS (
    SELECT tnc.cert_id, trim(d.fqdn) AS fqdn
    FROM tmp_new_certs tnc
    CROSS JOIN LATERAL unnest(string_to_array(tnc.dnsnames, ' ')) AS d(fqdn)
    WHERE tnc.dnsnames <> '' AND trim(d.fqdn) <> ''
),
unique_fqdns AS (
    SELECT DISTINCT fqdn
    FROM expanded
),
parsed AS (
    SELECT uf.fqdn, (p.parts).wild, (p.parts).www, (p.parts).domain, (p.parts).tld
    FROM unique_fqdns uf
    CROSS JOIN LATERAL (
        SELECT CERTDB_split_domain(uf.fqdn) AS parts
    ) AS p
),
cert_domains AS (
    SELECT e.cert_id, p.wild, p.www, p.domain, p.tld
    FROM expanded e
    INNER JOIN parsed p ON p.fqdn = e.fqdn
)
INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
SELECT DISTINCT cert_id, wild, www, domain, tld
FROM cert_domains
WHERE domain <> '' AND tld <> ''
$sql$;
BEGIN
    PERFORM set_config('synchronous_commit', 'off', true);

    debug_enabled = COALESCE(current_setting('certstream.debug', true), '') = 'on';
    IF debug_enabled THEN
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

    -- Each unique certificate must be processed only once.
    -- A certificate may be present in the database already,
    -- and it may appear multiple times in the indata.
    -- Even if a certificate is duplicated or already present
    -- in the database, CERTDB_entry must still be inserted into.

    PERFORM CERTDB_ingest_exec(debug_enabled, 'tmp_ingest', tmp_ingest_sql, _rows);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'ident_insert', ident_insert_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'tmp_new_certs', tmp_new_certs_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_uri', insert_uri_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_email', insert_email_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_ip', insert_ip_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_domain', insert_domain_sql, NULL);
END;
$$;
