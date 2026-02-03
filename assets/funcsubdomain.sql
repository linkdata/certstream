CREATE OR REPLACE FUNCTION CERTDB_subdomain(
  p_rev_domain text,
  p_tlds text
)
RETURNS TABLE (
  subdomain text,
  wild boolean,
  www smallint,
  tld text,
  issuer text,
  subject text,
  notbefore timestamp,
  notafter timestamp,
  since timestamp,
  sha256 text
)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  cn_rows integer := 0;
  recalc_rows integer := 0;
BEGIN
  CREATE TEMP TABLE IF NOT EXISTS tmp_certdb_subdomain_results (
    cert_id bigint,
    commonname text,
    subject_id integer,
    issuer_id integer,
    precert boolean,
    subdomain text,
    wild boolean,
    www smallint,
    tld text,
    issuer text,
    subject text,
    notbefore timestamp,
    notafter timestamp,
    since timestamp,
    sha256 text
  ) ON COMMIT DROP;

  TRUNCATE tmp_certdb_subdomain_results;

  INSERT INTO tmp_certdb_subdomain_results
  SELECT
    cc.id AS cert_id,
    cc.commonname,
    cc.subject AS subject_id,
    cc.issuer AS issuer_id,
    cc.precert,
    substring(cd.domain for char_length(cd.domain) - char_length(p_rev_domain)) AS subdomain,
    cd.wild,
    cd.www,
    cd.tld,
    iss.organization AS issuer,
    subj.organization AS subject,
    cc.notbefore,
    cc.notafter,
    cc.since,
    encode(cc.sha256, 'hex'::text) AS sha256
  FROM CERTDB_domain cd
  JOIN CERTDB_cert cc ON cc.id = cd.cert
  JOIN CERTDB_ident subj ON subj.id = cc.subject
  JOIN CERTDB_ident iss ON iss.id = cc.issuer
  WHERE reverse(cd.domain) LIKE p_rev_domain || '%'
    AND cd.tld = ANY(string_to_array(p_tlds, ' '))
    AND cc.precert = false
    AND NOT EXISTS (
      SELECT 1
      FROM CERTDB_cert newer
      WHERE newer.commonname = cc.commonname
        AND newer.subject = cc.subject
        AND newer.issuer = cc.issuer
        AND newer.precert = false
        AND cc.since IS NOT NULL
        AND newer.since = cc.since
        AND (
          newer.notbefore > cc.notbefore
          OR (newer.notbefore = cc.notbefore AND newer.id > cc.id)
        )
    );

  UPDATE CERTDB_cert c
  SET since = c.notbefore
  FROM tmp_certdb_subdomain_results r
  WHERE c.id = r.cert_id
    AND r.commonname = ''
    AND c.since IS DISTINCT FROM c.notbefore;
  GET DIAGNOSTICS cn_rows = ROW_COUNT;

  WITH affected_keys AS (
    SELECT DISTINCT r.commonname, r.subject_id, r.issuer_id, r.precert
    FROM tmp_certdb_subdomain_results r
    WHERE r.commonname <> ''
  ),
    ordered AS (
      SELECT
        c.id,
        c.commonname,
        c.subject,
        c.issuer,
        c.precert,
        c.notbefore,
        c.notafter,
        c.since,
        max(c.notafter) OVER (
          PARTITION BY c.commonname, c.subject, c.issuer, c.precert
          ORDER BY c.notbefore
          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS max_notafter
      FROM CERTDB_cert c
      JOIN affected_keys k
        ON c.commonname = k.commonname
       AND c.subject = k.subject_id
       AND c.issuer = k.issuer_id
       AND c.precert = k.precert
    ),
    marked AS (
      SELECT
        o.*,
        lag(o.max_notafter) OVER (
          PARTITION BY o.commonname, o.subject, o.issuer, o.precert
          ORDER BY o.notbefore
        ) AS prev_max
      FROM ordered o
    ),
    groups AS (
      SELECT
        m.*,
        sum(
          CASE
            WHEN m.prev_max IS NULL THEN 0
            WHEN m.notbefore > m.prev_max THEN 1
            ELSE 0
          END
        ) OVER (
          PARTITION BY m.commonname, m.subject, m.issuer, m.precert
          ORDER BY m.notbefore
          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS grp
      FROM marked m
    ),
    chain_min AS (
      SELECT
        g.commonname,
        g.subject,
        g.issuer,
        g.precert,
        g.grp,
        min(g.notbefore) AS since_calc
      FROM groups g
      GROUP BY g.commonname, g.subject, g.issuer, g.precert, g.grp
    ),
    targets AS (
      SELECT g.id, c.since_calc
      FROM groups g
      JOIN chain_min c
        ON g.commonname = c.commonname
       AND g.subject = c.subject
       AND g.issuer = c.issuer
       AND g.precert = c.precert
       AND g.grp = c.grp
    )
    UPDATE CERTDB_cert c
    SET since = t.since_calc
    FROM targets t
    WHERE c.id = t.id
      AND c.since IS DISTINCT FROM t.since_calc;
  GET DIAGNOSTICS recalc_rows = ROW_COUNT;

  IF cn_rows + recalc_rows > 0 THEN

    TRUNCATE tmp_certdb_subdomain_results;

    INSERT INTO tmp_certdb_subdomain_results
    SELECT
      cc.id AS cert_id,
      cc.commonname,
      cc.subject AS subject_id,
      cc.issuer AS issuer_id,
      cc.precert,
      substring(cd.domain for char_length(cd.domain) - char_length(p_rev_domain)) AS subdomain,
      cd.wild,
      cd.www,
      cd.tld,
      iss.organization AS issuer,
      subj.organization AS subject,
      cc.notbefore,
      cc.notafter,
      cc.since,
      encode(cc.sha256, 'hex'::text) AS sha256
    FROM CERTDB_domain cd
    JOIN CERTDB_cert cc ON cc.id = cd.cert
    JOIN CERTDB_ident subj ON subj.id = cc.subject
    JOIN CERTDB_ident iss ON iss.id = cc.issuer
    WHERE reverse(cd.domain) LIKE p_rev_domain || '%'
      AND cd.tld = ANY(string_to_array(p_tlds, ' '))
      AND cc.precert = false
      AND NOT EXISTS (
        SELECT 1
        FROM CERTDB_cert newer
        WHERE newer.commonname = cc.commonname
          AND newer.subject = cc.subject
          AND newer.issuer = cc.issuer
          AND newer.precert = false
          AND cc.since IS NOT NULL
          AND newer.since = cc.since
          AND (
            newer.notbefore > cc.notbefore
            OR (newer.notbefore = cc.notbefore AND newer.id > cc.id)
          )
      );
  END IF;

  RETURN QUERY
  SELECT
    r.subdomain,
    r.wild,
    r.www,
    r.tld,
    r.issuer,
    r.subject,
    r.notbefore,
    r.notafter,
    r.since,
    r.sha256
  FROM tmp_certdb_subdomain_results r;
END;
$$;
