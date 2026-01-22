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
        started_at = clock_timestamp();
        IF _arg IS NULL THEN
            FOR plan_line IN EXECUTE format('EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) %s', _statement_sql) LOOP
                IF plan_text = '' THEN
                    plan_text = plan_line;
                ELSE
                    plan_text = plan_text || E'\n' || plan_line;
                END IF;
            END LOOP;
        ELSE
            FOR plan_line IN EXECUTE format('EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) %s', _statement_sql) USING _arg LOOP
                IF plan_text = '' THEN
                    plan_text = plan_line;
                ELSE
                    plan_text = plan_text || E'\n' || plan_line;
                END IF;
            END LOOP;
        END IF;
        finished_at = clock_timestamp();
    ELSE
        started_at = clock_timestamp();
        IF _arg IS NULL THEN
            EXECUTE _statement_sql;
        ELSE
            EXECUTE _statement_sql USING _arg;
        END IF;
        finished_at = clock_timestamp();
    END IF;

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
    has_missing_idents boolean;
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
    tmp_new_certs_sql text := $sql$
CREATE TEMP TABLE tmp_new_certs ON COMMIT DROP AS
WITH unique_certs AS (
    SELECT DISTINCT ON (sha256)
        sha256,
        notbefore,
        notafter,
        commonname,
        iss_org,
        iss_prov,
        iss_country,
        sub_org,
        sub_prov,
        sub_country,
        precert,
        dnsnames,
        ipaddrs,
        emails,
        uris
    FROM tmp_ingest
    ORDER BY sha256
),
new_certs AS (
    SELECT uc.*
    FROM unique_certs uc
    LEFT JOIN CERTDB_cert c ON c.sha256 = uc.sha256
    WHERE c.id IS NULL
)
SELECT
    nc.*,
    NULL::integer AS iss_id,
    NULL::integer AS sub_id
FROM new_certs nc
$sql$;
    update_issuer_id_sql text := $sql$
UPDATE tmp_new_certs t
SET iss_id = i.id
FROM CERTDB_ident i
WHERE t.iss_id IS NULL
  AND i.organization = t.iss_org
  AND i.province = t.iss_prov
  AND i.country = t.iss_country
$sql$;
    update_subject_id_sql text := $sql$
UPDATE tmp_new_certs t
SET sub_id = i.id
FROM CERTDB_ident i
WHERE t.sub_id IS NULL
  AND i.organization = t.sub_org
  AND i.province = t.sub_prov
  AND i.country = t.sub_country
$sql$;
    ident_insert_sql text := $sql$
WITH needed_idents AS (
    SELECT DISTINCT iss_org AS organization, iss_prov AS province, iss_country AS country
    FROM tmp_new_certs
    WHERE iss_id IS NULL
    UNION
    SELECT DISTINCT sub_org AS organization, sub_prov AS province, sub_country AS country
    FROM tmp_new_certs
    WHERE sub_id IS NULL
)
INSERT INTO CERTDB_ident(organization, province, country)
SELECT n.organization, n.province, n.country
FROM needed_idents n
ON CONFLICT (organization, province, country) DO NOTHING
$sql$;
    insert_certs_sql text := $sql$
CREATE TEMP TABLE tmp_inserted_certs ON COMMIT DROP AS
WITH certs_with_since AS (
    SELECT
        t.sha256,
        t.notbefore,
        t.notafter,
        CASE
            WHEN t.commonname = '' THEN t.notbefore
            ELSE COALESCE(overlap.since, t.notbefore)
        END AS since,
        t.commonname,
        t.sub_id AS subject,
        t.iss_id AS issuer,
        t.precert
    FROM tmp_new_certs t
    LEFT JOIN LATERAL (
        SELECT c.since
        FROM CERTDB_cert c
        WHERE t.commonname <> ''
          AND c.subject = t.sub_id
          AND c.issuer = t.iss_id
          AND c.commonname = t.commonname
          AND c.notafter >= t.notbefore
          AND c.notbefore < t.notbefore
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
)
SELECT id AS cert_id, sha256
FROM cert_inserts
$sql$;
    insert_entry_sql text := $sql$
INSERT INTO CERTDB_entry(seen, logindex, cert, stream)
SELECT ti.seen, ti.logindex, c.id, ti.stream
FROM tmp_ingest ti
INNER JOIN CERTDB_cert c ON c.sha256 = ti.sha256
ON CONFLICT (stream, logindex) DO NOTHING
$sql$;
    insert_uri_sql text := $sql$
INSERT INTO CERTDB_uri (cert, uri)
-- uris are pre-trimmed in input; only filter empties
SELECT DISTINCT tic.cert_id, u.uri
FROM tmp_inserted_certs tic
INNER JOIN tmp_new_certs tnc ON tnc.sha256 = tic.sha256
CROSS JOIN LATERAL unnest(string_to_array(tnc.uris, ' ')) AS u(uri)
WHERE tnc.uris <> '' AND u.uri <> ''
ON CONFLICT (cert, uri) DO NOTHING
$sql$;
    insert_email_sql text := $sql$
INSERT INTO CERTDB_email (cert, email)
-- emails are pre-trimmed in input; only filter empties
SELECT DISTINCT tic.cert_id, e.email
FROM tmp_inserted_certs tic
INNER JOIN tmp_new_certs tnc ON tnc.sha256 = tic.sha256
CROSS JOIN LATERAL unnest(string_to_array(tnc.emails, ' ')) AS e(email)
WHERE tnc.emails <> '' AND e.email <> ''
ON CONFLICT (cert, email) DO NOTHING
$sql$;
    insert_ip_sql text := $sql$
WITH ip_data AS (
    -- ipaddrs are pre-trimmed in input; only filter empties
    SELECT DISTINCT tic.cert_id, ip.addr AS addr_txt
    FROM tmp_inserted_certs tic
    INNER JOIN tmp_new_certs tnc ON tnc.sha256 = tic.sha256
    CROSS JOIN LATERAL unnest(string_to_array(tnc.ipaddrs, ' ')) AS ip(addr)
    WHERE tnc.ipaddrs <> '' AND ip.addr <> ''
)
INSERT INTO CERTDB_ipaddress (cert, addr)
SELECT cert_id, inet(addr_txt)
FROM ip_data
ON CONFLICT (cert, addr) DO NOTHING
$sql$;
    insert_domain_sql text := $sql$
WITH expanded AS MATERIALIZED (
    -- dnsnames are pre-trimmed in input; split on space
    SELECT tic.cert_id, d.fqdn AS fqdn
    FROM tmp_inserted_certs tic
    INNER JOIN tmp_new_certs tnc ON tnc.sha256 = tic.sha256
    CROSS JOIN LATERAL unnest(string_to_array(tnc.dnsnames, ' ')) AS d(fqdn)
    WHERE tnc.dnsnames <> '' AND d.fqdn <> ''
),
unique_fqdns AS MATERIALIZED (
    SELECT DISTINCT fqdn
    FROM expanded
),
parsed AS MATERIALIZED (
    SELECT
        uf.fqdn,
        (parts).wild AS wild,
        (parts).www AS www,
        (parts).domain AS domain,
        (parts).tld AS tld
    FROM unique_fqdns uf
    CROSS JOIN LATERAL CERTDB_split_domain(uf.fqdn) AS parts
    WHERE (parts).domain <> '' AND (parts).tld <> ''
),
cert_domains AS (
    SELECT e.cert_id, p.wild, p.www, p.domain, p.tld
    FROM expanded e
    INNER JOIN parsed p ON p.fqdn = e.fqdn
)
INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
SELECT DISTINCT cert_id, wild, www, domain, tld
FROM cert_domains
$sql$;
BEGIN
    debug_enabled = COALESCE(current_setting('certstream.debug', true), '') = 'on';

    -- Each unique certificate must be processed only once.
    -- A certificate may be present in the database already,
    -- and it may appear multiple times in the indata.
    -- Even if a certificate is duplicated or already present
    -- in the database, CERTDB_entry must still be inserted into.

    PERFORM CERTDB_ingest_exec(debug_enabled, 'tmp_ingest', tmp_ingest_sql, _rows);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'tmp_new_certs', tmp_new_certs_sql, NULL);

    PERFORM CERTDB_ingest_exec(debug_enabled, 'update_issuer_ids', update_issuer_id_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'update_subject_ids', update_subject_id_sql, NULL);

    SELECT EXISTS (
        SELECT 1
        FROM tmp_new_certs
        WHERE iss_id IS NULL OR sub_id IS NULL
    ) INTO has_missing_idents;
    IF has_missing_idents THEN
        PERFORM CERTDB_ingest_exec(debug_enabled, 'ident_insert', ident_insert_sql, NULL);
        PERFORM CERTDB_ingest_exec(debug_enabled, 'update_issuer_ids', update_issuer_id_sql, NULL);
        PERFORM CERTDB_ingest_exec(debug_enabled, 'update_subject_ids', update_subject_id_sql, NULL);
    END IF;

    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_certs', insert_certs_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_uri', insert_uri_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_email', insert_email_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_ip', insert_ip_sql, NULL);
    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_domain', insert_domain_sql, NULL);

    PERFORM CERTDB_ingest_exec(debug_enabled, 'insert_entries', insert_entry_sql, NULL);
END;
$$;
