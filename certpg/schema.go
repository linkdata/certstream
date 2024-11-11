package certpg

var TablePrefix = "certdb_"

var Initialize = `
CREATE EXTENSION IF NOT EXISTS pg_trgm;
`

var TableOperator = `CREATE TABLE IF NOT EXISTS CERTDB_operator (
id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
name TEXT NOT NULL,
email TEXT NOT NULL,
UNIQUE(name, email)
);
`

var TableStream = `CREATE TABLE IF NOT EXISTS CERTDB_stream (
id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
url TEXT NOT NULL UNIQUE,
operator INTEGER NOT NULL REFERENCES CERTDB_operator (id),
json TEXT NOT NULL
);
`

var TableIdent = `CREATE TABLE IF NOT EXISTS CERTDB_ident (
id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
organization TEXT,
province TEXT,
country TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS CERTDB_ident_full_idx ON CERTDB_ident (organization, province, country);
INSERT INTO CERTDB_ident (organization, province, country) VALUES ('', '', '')
	ON CONFLICT (organization, province, country) DO NOTHING;
`

var TableCert = `CREATE TABLE IF NOT EXISTS CERTDB_cert (
id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
notbefore TIMESTAMP NOT NULL,
notafter TIMESTAMP NOT NULL,
commonname TEXT,
subject INTEGER NOT NULL REFERENCES CERTDB_ident (id),
issuer INTEGER NOT NULL REFERENCES CERTDB_ident (id),
sha256 BYTEA NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS CERTDB_cert_sha256_idx ON CERTDB_cert (sha256);
`

var TableEntry = `CREATE TABLE IF NOT EXISTS CERTDB_entry (
seen TIMESTAMP NOT NULL DEFAULT NOW(),
logindex BIGINT NOT NULL,
cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
stream INTEGER NOT NULL REFERENCES CERTDB_stream (id),
PRIMARY KEY (stream, logindex)
);
`

var TableDNSName = `CREATE TABLE IF NOT EXISTS CERTDB_dnsname (
cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
dnsname TEXT NOT NULL,
PRIMARY KEY (cert, dnsname)
);
CREATE INDEX IF NOT EXISTS CERTDB_dnsname_idx ON CERTDB_dnsname USING GIN (dnsname gin_trgm_ops);
`

var TableIPAddress = `CREATE TABLE IF NOT EXISTS CERTDB_ipaddress (
cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
addr INET NOT NULL,
PRIMARY KEY (cert, addr)
);
CREATE INDEX IF NOT EXISTS CERTDB_ipaddress_addr_idx ON CERTDB_ipaddress (addr);
`

var TableEmail = `CREATE TABLE IF NOT EXISTS CERTDB_email (
cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
email TEXT NOT NULL,
PRIMARY KEY (cert, email)
);
CREATE INDEX IF NOT EXISTS CERTDB_email_email_idx ON CERTDB_email (email);
`

var TableURI = `CREATE TABLE IF NOT EXISTS CERTDB_uri (
cert BIGINT NOT NULL REFERENCES CERTDB_cert (id),
uri TEXT NOT NULL,
PRIMARY KEY (cert, uri)
);
CREATE INDEX IF NOT EXISTS CERTDB_uri_uri_idx ON CERTDB_uri (uri);
`

var ViewDNSName = `CREATE OR REPLACE VIEW CERTDB_crtsh AS
SELECT cert, dnsname, 
	dnsname !~ '^[[:ascii:]]+$'::text AS idna, 
	NOW() between cc.notbefore and cc.notafter as valid,
	iss.organization as issuer,
	subj.organization as subject,
	concat('https://crt.sh/?q=', encode(cc.sha256, 'hex'::text)) AS crtsh
	FROM CERTDB_dnsname cd
	inner join CERTDB_cert cc on cc.id = cd.cert 
	inner join CERTDB_ident subj on subj.id = cc.subject
	inner join CERTDB_ident iss on iss.id = cc.issuer
;
`

var FunctionOperatorID = `
CREATE OR REPLACE FUNCTION CERTDB_operator_id(
IN s_name TEXT,
IN s_email TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
	_id INTEGER;
BEGIN
	SELECT id FROM CERTDB_operator INTO _id WHERE name=s_name AND email=s_email;
	IF NOT FOUND THEN
		INSERT INTO CERTDB_operator (name, email) VALUES (s_name, s_email)
			ON CONFLICT DO NOTHING RETURNING id INTO _id;
	END IF;
	IF NOT FOUND THEN
		SELECT id FROM CERTDB_operator INTO _id WHERE name=s_name AND email=s_email;
	END IF;
	RETURN _id;
END;
$$
;
`

var FunctionStreamID = `
CREATE OR REPLACE FUNCTION CERTDB_stream_id(
IN s_url TEXT,
IN s_operator BIGINT,
IN s_json TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
	_id INTEGER;
BEGIN
	SELECT id FROM CERTDB_stream INTO _id WHERE url=s_url;
	IF NOT FOUND THEN
		INSERT INTO CERTDB_stream (url, operator, json) VALUES (s_url, s_operator, s_json)
			ON CONFLICT DO NOTHING RETURNING id INTO _id;
	END IF;
	IF NOT FOUND THEN
		SELECT id FROM CERTDB_stream INTO _id WHERE url=s_url;
	END IF;
	RETURN _id;
END;
$$
;
`

var ProcedureNewEntry = `
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

	INSERT INTO CERTDB_cert (notbefore, notafter, commonname, subject, issuer, sha256)
		VALUES (notbefore, notafter, commonname, _sub_id, _iss_id, hash)
		ON CONFLICT (sha256) DO NOTHING RETURNING id INTO _cert_id;
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
`

var SelectGaps = `SELECT logindex + 1 AS gap_start, next_nr - 1 AS gap_end
FROM (
  SELECT logindex, LEAD(logindex) OVER (ORDER BY logindex) AS next_nr FROM CERTDB_entry WHERE stream = $1
)
WHERE logindex + 1 <> next_nr;
`

var SelectMinIndex = `SELECT MIN(logindex) AS logindex FROM CERTDB_entry WHERE stream = $1;`
