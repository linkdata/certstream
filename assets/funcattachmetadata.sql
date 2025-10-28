CREATE OR REPLACE FUNCTION CERTDB_attach_metadata(
    _cert_id  bigint,
    _dnsnames text,
    _ipaddrs  text,
    _emails   text,
    _uris     text
) RETURNS void
LANGUAGE sql
AS $$
INSERT INTO CERTDB_uri (cert, uri)
SELECT _cert_id, unnest(string_to_array(coalesce(_uris, ''), ' '))
ON CONFLICT (cert, uri) DO NOTHING;

INSERT INTO CERTDB_email (cert, email)
SELECT _cert_id, unnest(string_to_array(coalesce(_emails, ''), ' '))
ON CONFLICT (cert, email) DO NOTHING;

INSERT INTO CERTDB_ipaddress (cert, addr)
SELECT _cert_id, inet(unnest(string_to_array(coalesce(_ipaddrs, ''), ' ')))
ON CONFLICT (cert, addr) DO NOTHING;

INSERT INTO CERTDB_domain (cert, wild, www, domain, tld)
SELECT
  _cert_id,
  (s).wild,
  (s).www,
  (s).domain,
  (s).tld
FROM (
  SELECT CERTDB_split_domain(fqdn) AS s
  FROM unnest(string_to_array(coalesce(_dnsnames, ''), ' ')) AS fqdn
) x
WHERE (s).domain <> '' AND (s).tld <> '';
$$;
