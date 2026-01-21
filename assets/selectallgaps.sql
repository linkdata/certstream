WITH CERTDB_findgap_STREAMID_LOGINDEX AS (
  SELECT $2::bigint AS logindex
  WHERE $2::bigint >= 0
),
base AS (
  SELECT logindex
  FROM CERTDB_entry
  WHERE stream = $1
    AND logindex > $2::bigint
    AND logindex <= $3::bigint
  ORDER BY logindex ASC
  LIMIT $4
),
scan_rows AS (
  SELECT logindex FROM CERTDB_findgap_STREAMID_LOGINDEX
  UNION ALL
  SELECT logindex FROM base
),
candidates AS (
  SELECT s.logindex AS prev_logindex,
    n.logindex AS next_logindex
  FROM scan_rows s
  JOIN LATERAL (
    SELECT logindex
    FROM CERTDB_entry
    WHERE stream = $1
      AND logindex > s.logindex
      AND logindex <= $3::bigint
    ORDER BY logindex ASC
    LIMIT 1
  ) n ON true
  WHERE n.logindex > s.logindex + 1
  ORDER BY s.logindex ASC
  LIMIT 1
),
last AS (
  SELECT MAX(logindex) AS last_logindex FROM base
)
SELECT
  c.prev_logindex + 1 AS gap_start,
  c.next_logindex - 1 AS gap_end,
  last.last_logindex
FROM last
LEFT JOIN candidates c ON true;
