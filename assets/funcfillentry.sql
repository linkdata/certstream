CREATE OR REPLACE FUNCTION CERTDB_fill_entry(
	_cert_id BIGINT,
	_dnsnames TEXT,
	_ipaddrs TEXT,
	_emails TEXT,
	_uris TEXT
)
RETURNS BIGINT
LANGUAGE sql
BEGIN ATOMIC;
	INSERT INTO CERTDB_dnsname (cert, dnsname) VALUES (_cert_id, UNNEST(STRING_TO_ARRAY(_dnsnames, ' '))) ON CONFLICT (cert, dnsname) DO NOTHING;
    INSERT INTO CERTDB_email (cert, email) VALUES (_cert_id, UNNEST(STRING_TO_ARRAY(_emails, ' '))) ON CONFLICT (cert, email) DO NOTHING;
    INSERT INTO CERTDB_uri (cert, uri) VALUES (_cert_id, UNNEST(STRING_TO_ARRAY(_uris, ' '))) ON CONFLICT (cert, uri) DO NOTHING;
    INSERT INTO CERTDB_ipaddress (cert, addr) VALUES (_cert_id, inet(UNNEST(STRING_TO_ARRAY(_ipaddrs, ' ')))) ON CONFLICT (cert, addr) DO NOTHING;
	SELECT _cert_id;
END;