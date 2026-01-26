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
  sha256 text,
  precert boolean
)
LANGUAGE sql
STABLE
AS $$
SELECT
  substring(cd.domain for char_length(cd.domain) - char_length($1)) AS subdomain,
  cd.wild,
  cd.www,
  cd.tld,
  iss.organization AS issuer,
  subj.organization AS subject,
  cc.notbefore,
  cc.notafter,
  cc.since,
  encode(cc.sha256, 'hex'::text) AS sha256,
  cc.precert AS precert
FROM CERTDB_domain cd
JOIN CERTDB_cert cc ON cc.id = cd.cert
JOIN CERTDB_ident subj ON subj.id = cc.subject
JOIN CERTDB_ident iss ON iss.id = cc.issuer
WHERE reverse(cd.domain) LIKE $1 || '%'
  AND cd.tld = ANY(string_to_array($2, ' '))
  AND NOT EXISTS (
    SELECT 1
    FROM CERTDB_cert newer
    WHERE newer.commonname = cc.commonname
      AND newer.subject = cc.subject
      AND newer.issuer = cc.issuer
      AND newer.since IS NOT DISTINCT FROM cc.since
      AND (
        newer.notbefore > cc.notbefore
        OR (newer.notbefore = cc.notbefore AND newer.id > cc.id)
      )
  );
$$;
