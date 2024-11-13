CREATE OR REPLACE PROCEDURE CERTDB_new_entry(
  IN seen TIMESTAMP,
  IN stream INTEGER, 
  IN logindex BIGINT, 
  IN hash BYTEA, 
  IN iss_org TEXT, 
  IN iss_prov TEXT, 
  IN iss_country TEXT, 
  IN sub_org TEXT, 
  IN sub_prov TEXT, 
  IN sub_country TEXT, 
  IN notbefore TIMESTAMP,
  IN notafter TIMESTAMP,
  IN commonname TEXT,
  IN dnsnames TEXT,
  IN ipaddrs TEXT,
  IN emails TEXT,
  IN uris TEXT
)
LANGUAGE plpgsql
AS $procedure$
DECLARE
  _iss_id INTEGER;
  _sub_id INTEGER;
  _cert_id BIGINT;
  _txt TEXT;
BEGIN

  SELECT id FROM CERTDB_ident INTO _iss_id WHERE organization=iss_org AND province=iss_prov AND country=iss_country;
  IF NOT FOUND THEN
    INSERT INTO CERTDB_ident (organization, province, country)
      VALUES (iss_org, iss_prov, iss_country)
      ON CONFLICT (organization, province, country) DO NOTHING RETURNING id INTO _iss_id;
  END IF;
  IF NOT FOUND THEN
    SELECT id FROM CERTDB_ident INTO _iss_id WHERE organization=iss_org AND province=iss_prov AND country=iss_country;
  END IF;

  SELECT id FROM CERTDB_ident INTO _sub_id WHERE organization=sub_org AND province=sub_prov AND country=sub_country;
  IF NOT FOUND THEN
    INSERT INTO CERTDB_ident (organization, province, country)
      VALUES (sub_org, sub_prov, sub_country)
      ON CONFLICT (organization, province, country) DO NOTHING RETURNING id INTO _sub_id;
  END IF;
  IF NOT FOUND THEN
    SELECT id FROM CERTDB_ident INTO _sub_id WHERE organization=sub_org AND province=sub_prov AND country=sub_country;
  END IF;

  SELECT id FROM CERTDB_cert INTO _cert_id WHERE sha256=hash;
  IF NOT FOUND THEN
    INSERT INTO CERTDB_cert (notbefore, notafter, commonname, subject, issuer, sha256)
      VALUES (notbefore, notafter, commonname, _sub_id, _iss_id, hash)
      ON CONFLICT (sha256) DO NOTHING RETURNING id INTO _cert_id;
  END IF;
  IF NOT FOUND THEN
    SELECT id FROM CERTDB_cert INTO _cert_id WHERE sha256=hash;
  END IF;

  FOREACH _txt IN ARRAY STRING_TO_ARRAY(dnsnames, ' ')
  LOOP
    INSERT INTO CERTDB_dnsname (cert, dnsname) VALUES (_cert_id, _txt) ON CONFLICT (cert, dnsname) DO NOTHING;
  END LOOP;
  FOREACH _txt IN ARRAY STRING_TO_ARRAY(ipaddrs, ' ')
  LOOP
    INSERT INTO CERTDB_ipaddress (cert, addr) VALUES (_cert_id, inet(_txt)) ON CONFLICT (cert, addr) DO NOTHING;
  END LOOP;
  FOREACH _txt IN ARRAY STRING_TO_ARRAY(emails, ' ')
  LOOP
    INSERT INTO CERTDB_email (cert, email) VALUES (_cert_id, _txt) ON CONFLICT (cert, email) DO NOTHING;
  END LOOP;
  FOREACH _txt IN ARRAY STRING_TO_ARRAY(uris, ' ')
  LOOP
    INSERT INTO CERTDB_uri (cert, uri) VALUES (_cert_id, _txt) ON CONFLICT (cert, uri) DO NOTHING;
  END LOOP;

  INSERT INTO CERTDB_entry (seen, logindex, cert, stream)
    VALUES (seen, logindex, _cert_id, stream)
    ON CONFLICT DO NOTHING;

  COMMIT;

END;
$procedure$
;
