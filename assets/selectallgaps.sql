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
) t
WHERE next_nr IS NOT NULL
  AND next_nr > logindex + 1
ORDER BY stream, gap_start;
