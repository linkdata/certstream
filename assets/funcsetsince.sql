CREATE OR REPLACE FUNCTION CERTDB_set_since(
  p_certid bigint
)
RETURNS timestamp
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  v_notbefore timestamp;
  v_commonname text;
  v_subject integer;
  v_issuer integer;
  v_precert boolean;
  v_calc timestamp;
BEGIN
  SELECT notbefore, commonname, subject, issuer, precert
  INTO v_notbefore, v_commonname, v_subject, v_issuer, v_precert
  FROM CERTDB_cert
  WHERE id = p_certid;

  IF v_notbefore IS NULL THEN
    RETURN NULL;
  END IF;

  IF v_commonname = '' THEN
    v_calc := v_notbefore;
  ELSE
    WITH RECURSIVE chain AS (
      SELECT v_notbefore AS notbefore
      UNION ALL
      SELECT prev.notbefore
      FROM chain
      JOIN LATERAL (
        SELECT c.notbefore
        FROM CERTDB_cert c
        WHERE c.subject = v_subject
          AND c.issuer = v_issuer
          AND c.commonname = v_commonname
          AND c.precert = v_precert
          AND c.notafter >= chain.notbefore
          AND c.notbefore < chain.notbefore
        ORDER BY c.notbefore DESC
        LIMIT 1
      ) prev ON TRUE
    )
    SELECT MIN(notbefore) INTO v_calc FROM chain;

    IF v_calc IS NULL THEN
      v_calc := v_notbefore;
    END IF;
  END IF;

  UPDATE CERTDB_cert
  SET since = v_calc
  WHERE id = p_certid;

  RETURN v_calc;
END;
$$;
