package certpg

var TablePrefix = "certdb_"

var Initialize = `
CREATE EXTENSION IF NOT EXISTS LTREE;

CREATE OR REPLACE FUNCTION array_reverse(anyarray) RETURNS anyarray AS $$
SELECT ARRAY(
    SELECT $1[i]
    FROM generate_subscripts($1,1) AS s(i)
    ORDER BY i DESC
);
$$ LANGUAGE 'sql' STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION rname_to_name(ltree) RETURNS TEXT AS $$
SELECT
	replace(
		reverse(
			array_to_string(
				array_reverse(
					string_to_array(
						reverse(ltree2text($1))
					,'.')
				),
			'.')
		),
	'STAR', '*');
$$ LANGUAGE 'sql' STRICT IMMUTABLE;
`

var TableOperator = `CREATE TABLE IF NOT EXISTS {Prefix}operator (
id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
name TEXT NOT NULL,
email TEXT NOT NULL,
UNIQUE(name, email)
);
`

var TableStream = `CREATE TABLE IF NOT EXISTS {Prefix}stream (
id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
url TEXT NOT NULL UNIQUE,
operator BIGINT NOT NULL REFERENCES {Prefix}operator (id),
lastindex BIGINT NOT NULL,
json TEXT NOT NULL
);
`

var TableIdent = `CREATE TABLE IF NOT EXISTS {Prefix}ident (
id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
organization TEXT,
province TEXT,
country TEXT,
UNIQUE (organization, province, country)
);
`

var TableCert = `CREATE TABLE IF NOT EXISTS {Prefix}cert (
id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
commonname TEXT,
subject BIGINT NOT NULL REFERENCES {Prefix}ident (id),
issuer BIGINT NOT NULL REFERENCES {Prefix}ident (id),
notbefore TIMESTAMP NOT NULL,
notafter TIMESTAMP NOT NULL,
sha256 BYTEA NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS {Prefix}cert_sha256_idx ON {Prefix}cert (sha256);
CREATE INDEX IF NOT EXISTS {Prefix}cert_commonname_idx ON {Prefix}cert (commonname);
CREATE INDEX IF NOT EXISTS {Prefix}cert_notbefore_idx ON {Prefix}cert (notbefore);
CREATE INDEX IF NOT EXISTS {Prefix}cert_notafter_idx ON {Prefix}cert (notafter);
`

var TableEntry = `CREATE TABLE IF NOT EXISTS {Prefix}entry (
stream BIGINT NOT NULL REFERENCES {Prefix}stream (id),
index BIGINT NOT NULL,
cert BIGINT NOT NULL REFERENCES {Prefix}cert (id),
PRIMARY KEY (stream, index)
);
`

var TableRDNSName = `CREATE TABLE IF NOT EXISTS {Prefix}rdnsname (
cert BIGINT NOT NULL REFERENCES {Prefix}cert (id),
rname LTREE NOT NULL,
PRIMARY KEY (cert, rname)
);
CREATE INDEX IF NOT EXISTS {Prefix}rdnsname_rname_idx ON {Prefix}rdnsname USING GIST (rname);
`

var ViewDNSName = `CREATE OR REPLACE VIEW {Prefix}dnsname AS
SELECT *,
	rname_to_name(rname) AS name,
	(SELECT CONCAT('https://crt.sh/?q=',encode(sha256, 'hex')) FROM {Prefix}cert WHERE {Prefix}cert.id=cert) AS crtsh
	FROM {Prefix}rdnsname;
`

var TableIPAddress = `CREATE TABLE IF NOT EXISTS {Prefix}ipaddress (
cert BIGINT NOT NULL REFERENCES {Prefix}cert (id),
addr INET NOT NULL,
PRIMARY KEY (cert, addr)
);
CREATE INDEX IF NOT EXISTS {Prefix}ipaddress_addr_idx ON {Prefix}ipaddress (addr);
`

var TableEmail = `CREATE TABLE IF NOT EXISTS {Prefix}email (
cert BIGINT NOT NULL REFERENCES {Prefix}cert (id),
email TEXT NOT NULL,
PRIMARY KEY (cert, email)
);
CREATE INDEX IF NOT EXISTS {Prefix}email_email_idx ON {Prefix}email (email);
`

var TableURI = `CREATE TABLE IF NOT EXISTS {Prefix}uri (
cert BIGINT NOT NULL REFERENCES {Prefix}cert (id),
uri TEXT NOT NULL,
PRIMARY KEY (cert, uri)
);
CREATE INDEX IF NOT EXISTS {Prefix}uri_uri_idx ON {Prefix}uri (uri);
`
