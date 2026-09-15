# Tuning PostgreSQL for certstream

A certstream database is unusual in three ways, and the rest of this document
follows from them:

- **Few tables, all enormous.** `CERTDB_entry` holds a row per certificate per
  log, `CERTDB_domain` a row per DNS name. Both reach billions of rows.
- **Indexes outweigh the heap.** `CERTDB_domain` carries four indexes over a
  text column, one of them a GIN trigram index.
- **Inserts are continuous, deletes arrive in sweeps.** Ingest never stops, and
  retention removes expired certificates in bulk.

Every autovacuum pass scans each of a table's indexes in full. On tables this
size that makes the cost of a pass large and *fixed*, while only the number of
dead rows it removes varies. Most of the tuning below is about making each pass
count.

None of it is needed for a database of a few hundred GB, where the defaults are
fine. The rates and ratios come from a multi-terabyte deployment on PostgreSQL
18; read them as orders of magnitude rather than as targets, and re-measure on
your own storage. Table names assume the default `Config.PgPrefix` of
`certdb_`.

## 1. Enable retention, or none of the rest matters

Cleanup is off unless [Config.PgCertMaxAge] is set, and a database without it
grows without bound:

```go
cfg := certstream.NewConfig()
cfg.PgCertMaxAge = 180 * 24 * time.Hour // delete certs 180 days after they expire
```

Two things worth knowing about what that does:

- Deletion walks `notafter` forward from a cursor, in batches of
  [CleanBatchSize]. The cursor is what keeps a batch cheap: it resumes where the
  previous batch stopped rather than re-traversing the dead index entries it
  already passed over. Without it the cost of a batch grows with the size of the
  backlog, which is how a database falls behind and stays behind.
- `VACUUM` marks space reusable inside the existing files; it does **not**
  return it to the filesystem. A tuned database stops *growing*; it does not
  shrink. Only `DROP` gives disk back for free; `REINDEX`, `VACUUM FULL` and
  `pg_repack` also do, but need room for a full copy first.

The library sets `synchronous_commit = off` per session unless
`Config.PgSyncCommit` is set, so there is no need to change it in the
configuration file.

## 2. postgresql.conf

### `autovacuum_work_mem`

This is the one server-wide setting worth changing. It bounds the dead tuples
vacuum can remember per pass; when a pass exceeds it, vacuum scans **every
index again** for each additional lap.

On PostgreSQL 17 and later a dead TID costs about **2.18 bytes**, so:

| `autovacuum_work_mem` | dead rows per index lap |
|---|---|
| 64 MB (the default `-1`, inheriting `maintenance_work_mem`) | ~30 M |
| 1 GB | ~492 M |
| 2 GB | ~985 M |

A pass that clears a retention backlog on a billion-row table can hold billions
of dead tuples at once — 2e9 of them need 4.1 GiB, so a 1 GB budget turns that
pass into four extra laps of every index on the table. On these tables a lap is
measured in TB of reads, which is why this setting is worth more than its size
suggests.

```
autovacuum_work_mem = 2GB
```

Budget for it: the ceiling is `autovacuum_max_workers` × this value, on top of
`shared_buffers`. It is a ceiling and not a reservation — the store grows only
as needed, and only the big tables approach it.

On PostgreSQL 16 and earlier the dead-tuple array is capped at 1 GB regardless
of the setting, which is about 178 M TIDs; there is no point going above that.

### What not to bother with

`autovacuum_max_workers` is rarely the constraint — the database has few tables
and each pass is long, so raising the count adds contention for the same disk
rather than parallelism. Raise it only if a pass is observed waiting for a
worker slot while the catalog tables consume the rest.

## 3. Per-table autovacuum settings

The three large tables need settings the global defaults cannot express. All of
these are `ALTER TABLE`, so they need table ownership rather than superuser, and
they take `SHARE UPDATE EXCLUSIVE`: reads and writes are unaffected, but a
running `VACUUM` on the table is cancelled and restarts from the beginning.

```sql
-- 1. The throttle. This is the one that matters.
ALTER TABLE certdb_cert   SET (autovacuum_vacuum_cost_limit = 10000);
ALTER TABLE certdb_domain SET (autovacuum_vacuum_cost_limit = 10000);
ALTER TABLE certdb_entry  SET (autovacuum_vacuum_cost_limit = 10000);

-- 2. Pay for a multi-TB index scan as rarely as the memory budget allows.
ALTER TABLE certdb_cert SET (
  autovacuum_vacuum_threshold           = 100000000,
  autovacuum_vacuum_scale_factor        = 0,
  autovacuum_vacuum_insert_threshold    = 100000000,
  autovacuum_vacuum_insert_scale_factor = 0
);
ALTER TABLE certdb_domain SET (autovacuum_vacuum_threshold = 100000000, autovacuum_vacuum_scale_factor = 0);
ALTER TABLE certdb_entry  SET (autovacuum_vacuum_threshold = 100000000, autovacuum_vacuum_scale_factor = 0);

-- 3. Statistics. Cheap, and the cleanup plans off the notafter histogram.
ALTER TABLE certdb_domain SET (autovacuum_analyze_threshold = 50000000, autovacuum_analyze_scale_factor = 0);
ALTER TABLE certdb_entry  SET (autovacuum_analyze_threshold = 50000000, autovacuum_analyze_scale_factor = 0);
```

**Why `cost_limit`.** The default 200, at the default 2 ms delay, caps a vacuum
worker at roughly 410 MB/s of reads or 41 MB/s of dirtied pages. Index
vacuuming sustains around 60 MB/s of btree on ordinary server storage, so the
default binds hard: at the dirty-page ceiling a 2 TB index set is some fourteen
hours of pure throttling per lap, and a table under a continuous delete stream
never catches up. At 10000 the throttle is effectively off and a pass runs at
whatever the disk gives. Note that this reallocates I/O toward vacuum rather
than creating capacity — if ingest suffers, 2000–5000 is a reasonable middle
ground. The point is to not be at 200.

**Why the thresholds.** The defaults are scale-factor driven, which is
meaningless at this size: at the default 0.2, a ten-billion-row table waits for
two billion dead rows, i.e. never. PostgreSQL 18 caps that at 100 M via
`autovacuum_vacuum_max_threshold`, and setting it per table makes the value
explicit rather than inherited — on PostgreSQL 17 and earlier, where the cap
does not exist, it is mandatory.

Going the other way matters too. A scale factor that puts the threshold at a few
million rows triggers the table's full multi-TB index scan dozens of times a
day; at 100 M it removes the same rows in an order of magnitude fewer scans, at
the price of holding more dead heap between passes — tens of GB against the
hundreds already free in a table this size. Do not raise it much beyond 100 M
without re-checking §2 — the threshold and the memory budget have to agree, or
the saving is spent on extra index laps.

## 4. The `CERTDB_domain` indexes

This table's vacuum cost is dominated by one index. Typical proportions:

| index | share of index bytes | type | used by |
|---|---|---|---|
| `certdb_domain_domain_tri_idx` | **~45%** | **GIN** | nothing in this library; substring (`%x%`) search |
| `certdb_domain_cert_idx` | ~21% | btree | the `ON DELETE CASCADE` from `CERTDB_cert` — **required** |
| `certdb_domain_domain_rev_idx` | ~18% | btree | `CERTDB_subdomain()`, via `reverse(domain) LIKE 'x%'` |
| `certdb_domain_domain_idx` | ~16% | btree | nothing in this library; forward prefix search |

GIN vacuum runs at roughly **3.9 MB/s** against the ~60 MB/s btree rate — about
15× slower per byte, which leaves that one index accounting for some 92% of a
pass that runs for days. No autovacuum setting helps: with `cost_limit` at its
maximum and the memory budget only a third used, the cost is `ginbulkdelete`
itself walking the entry tree and rewriting posting pages.

So if the application does not offer substring domain search, dropping
`certdb_domain_domain_tri_idx` cuts the pass by roughly an order of magnitude
and returns its bytes to the filesystem immediately. Dropping the two unused
btree indexes as well leaves only the cascade index, for a pass some 35×
shorter. Keep `certdb_domain_cert_idx` — it serves the cascade, and takes
essentially all of the table's index scans; the other three together take a
negligible share.

This is a product decision, not a performance one: rebuilding a GIN index of
this size later needs both the time and free space equal to the index. Check
what actually uses them first:

```sql
SELECT indexrelname, idx_scan, pg_size_pretty(pg_relation_size(indexrelid))
FROM pg_stat_user_indexes WHERE relname = 'certdb_domain' ORDER BY idx_scan;
```

## 5. Checking the result

```sql
-- Is a pass running, and is it on its second lap of the indexes?
SELECT p.pid, c.relname, p.phase, p.heap_blks_scanned, p.heap_blks_total,
       p.index_vacuum_count, pg_size_pretty(p.dead_tuple_bytes) -- max_dead_tuples before 17
FROM pg_stat_progress_vacuum p JOIN pg_class c ON c.oid = p.relid;

-- Dead tuples against the threshold each table now carries.
SELECT relname, n_live_tup, n_dead_tup, autovacuum_count, last_autovacuum
FROM pg_stat_user_tables WHERE relname LIKE 'certdb_%' ORDER BY n_dead_tup DESC;
```

Two ways to misread these:

- `autovacuum_count` and `last_autovacuum` only advance when a pass
  **completes**. On these tables a pass takes hours to days, so a stale
  `last_autovacuum` and a running vacuum together mean it is working, not
  stalled. Use `pg_stat_progress_vacuum` to tell the difference.
- `index_vacuum_count` counts completed index laps. More than one means the
  pass ran out of `autovacuum_work_mem` and scanned every index again. That is
  the signal §2 exists for.

[Config.PgCertMaxAge]: https://pkg.go.dev/github.com/linkdata/certstream#Config
[CleanBatchSize]: https://pkg.go.dev/github.com/linkdata/certstream#CleanBatchSize
