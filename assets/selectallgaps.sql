SELECT
  stream,
  gap_start,
  gap_end
FROM (
  SELECT
    stream,
    logindex + 1 AS gap_start,
    next_nr - 1 AS gap_end
  FROM (
    SELECT
      stream,
      logindex,
      LEAD(logindex) OVER (PARTITION BY stream ORDER BY logindex) AS next_nr
    FROM CERTDB_entry
    WHERE stream IN (%s)
      AND (stream > $1 OR (stream = $1 AND logindex >= $2::bigint - 1))
  ) t
  WHERE next_nr IS NOT NULL
    AND next_nr > logindex + 1
) gaps
WHERE (stream > $1::int OR (stream = $1 AND gap_start > $2::bigint))
ORDER BY stream, gap_start
LIMIT $3;
