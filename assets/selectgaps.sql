SELECT logindex + 1 AS gap_start, next_nr - 1 AS gap_end
FROM (SELECT logindex, LEAD(logindex) OVER (ORDER BY logindex) AS next_nr FROM CERTDB_entry WHERE stream = $1)
WHERE logindex + 1 <> next_nr
;
