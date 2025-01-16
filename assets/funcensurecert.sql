CREATE OR REPLACE FUNCTION CERTDB_ensure_cert(
	_notbefore TIMESTAMP,
	_notafter TIMESTAMP,
	_commonname TEXT,
	_subject BIGINT,
	_issuer BIGINT,
	_hash BYTEA,
	_precert BOOLEAN
)
RETURNS BIGINT
LANGUAGE sql
BEGIN ATOMIC;
	WITH neworexisting AS (
		INSERT INTO CERTDB_cert (notbefore, notafter, commonname, subject, issuer, sha256, precert)
		VALUES (_notbefore, _notafter, _commonname, _subject, _issuer, _hash, _precert)
		ON CONFLICT (sha256) DO UPDATE SET precert=_precert
		RETURNING id
	)
	SELECT id FROM neworexisting;
END;