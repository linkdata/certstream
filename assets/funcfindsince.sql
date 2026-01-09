CREATE OR REPLACE FUNCTION CERTDB_find_since(
  _commonname text,
  _subject    integer,
  _issuer     integer,
  _notbefore  timestamp
)
RETURNS timestamp
LANGUAGE sql
AS $$
  SELECT
    CASE
      WHEN $1 = '' THEN $4
      ELSE (
        WITH candidates AS (
          SELECT notbefore, notafter
          FROM CERTDB_cert
          WHERE commonname = $1
            AND subject    = $2
            AND issuer     = $3
            AND notbefore <= $4
          ORDER BY notbefore DESC
          LIMIT 365
        ),
        tagged AS (
          SELECT
            notbefore,
            notafter,
            LAG(notbefore) OVER (ORDER BY notbefore DESC) AS newer_notbefore
          FROM candidates
        ),
        breaks AS (
          SELECT
            notbefore,
            SUM(
              CASE
                WHEN newer_notbefore IS NULL THEN 0
                WHEN notafter < newer_notbefore THEN 1
                ELSE 0
              END
            ) OVER (ORDER BY notbefore DESC ROWS UNBOUNDED PRECEDING) AS break_group
          FROM tagged
        )
        SELECT MIN(notbefore)
        FROM breaks
        WHERE break_group = 0
      )
    END;
$$;
