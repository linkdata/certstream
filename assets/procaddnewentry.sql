CREATE OR REPLACE PROCEDURE CERTDB_add_new_entry(
  _seen TIMESTAMP,
  _stream INTEGER,
  _logindex BIGINT,
  _precert BOOLEAN,
  _hash BYTEA,
  _issuer BIGINT,
  _subject BIGINT,
  _notbefore TIMESTAMP,
  _notafter TIMESTAMP,
  _commonname TEXT,
  _dnsnames TEXT,
  _ipaddrs TEXT,
  _emails TEXT,
  _uris TEXT
)
LANGUAGE plpgsql AS
$proc$
DECLARE
  _cert_id INTEGER;
BEGIN
	SELECT CERTDB_new_entry(
		_seen,
		_stream, 
		_logindex, 
		_precert,
		_hash, 
		_iss_org, 
		_iss_prov, 
		_iss_country, 
		_sub_org, 
		_sub_prov, 
		_sub_country, 
		_notbefore,
		_notafter,
		_commonname,
		_dnsnames,
		_ipaddrs,
		_emails,
		_uris
	) INTO _cert_id;
	IF FOUND THEN
		COMMIT;
	ELSE
		ROLLBACK;
	END IF;
END
$proc$;
