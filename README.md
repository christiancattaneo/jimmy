# jimmy

pries open the database the application thinks is locked.

site: https://jimmy-sage.vercel.app

a crowbar tests the front door. jimmy tests the **basement** the front door is hiding. it pokes at the gaps the other tools miss: row-level security, multi-tenant isolation, transactional anomalies, schema integrity, and migration safety.

inspired by jepsen and elle, but pointed one layer up: at your application's use of the database, not the database engine itself.

## what it finds

slopometer, pinata, whackamole, crowbar, orion all touch the database, but only at the edges: injection at the query string, pool exhaustion, capacity. jimmy covers the rest.

- **rls bypass**: tables with rls disabled, permissive `USING (true)` policies, columns reachable as the anon role, policies that depend on `auth.uid()` but are reachable unauthenticated
- **rpc bypass**: `SECURITY DEFINER` functions callable by anon/authenticated (they run as the owner and skip the caller's rls), and definer functions without a pinned `search_path` (name-resolution hijack, a cve-class hazard)
- **storage leaks**: public supabase storage buckets, buckets with no file-size limit, `storage.objects` with rls disabled, and permissive `USING(true)` storage policies granted to public roles
- **realtime leaks**: tables in the `supabase_realtime` publication with rls disabled (every change is streamed to subscribers with no filtering) or with rls on but no policy
- **scheduled jobs**: pg_cron jobs that run as a privileged role with no request context (rls bypassed by design), flagging those that do DML as a superuser or call out over pg_net
- **multi-tenant leakage**: seed two tenants, authenticate as A, prove A cannot read, update, or delete any of B's rows across every table. mechanically enumerated from the schema
- **transaction anomalies**: hermitage-style probes for lost update, write skew, read skew, and G2 (anti-dependency cycles). run at every isolation level and assert the database actually behaves the way the app assumes
- **schema integrity**: missing foreign keys, weak `NOT NULL`, missing `UNIQUE`, missing `CHECK`, soft-delete columns referenced inconsistently, nullable columns the app code assumes are non-null
- **migration safety**: squawk-style linter for dangerous DDL: `ALTER TABLE ... ADD COLUMN ... NOT NULL` without default, non-`CONCURRENTLY` index creation, type rewrites, dropping columns still referenced
- **n+1 detection**: groups query templates from `pg_stat_statements` or a recorded log, flags repeated executions per request

## install

run it without installing (the binary is named `jimmy`):

```bash
npx jimmy-db migrations lint --dir ./supabase/migrations
npx jimmy-db rls audit --db $DATABASE_URL
```

or install globally:

```bash
npm install -g jimmy-db
jimmy scan --db $DATABASE_URL
```

from source:

```bash
npm install
npm run build
node dist/cli/index.js --help
```

## usage

every command takes a connection string. **jimmy refuses to run on a database whose name contains `prod`, `production`, or `live` without `--i-know-what-im-doing`.** read-only by default. property tests use a dedicated test schema.

### scan everything

```bash
jimmy scan \
  --db postgres://user:pass@localhost:5432/myapp \
  --output jimmy-report
```

runs every check that doesn't mutate the database. produces `jimmy-report.md` and `jimmy-report.json`.

### just rls

```bash
# static introspection only (read-only, instant). includes the rpc /
# SECURITY DEFINER audit.
jimmy rls audit --db $DATABASE_URL

# property test (creates throwaway tenants in a test schema)
jimmy rls fuzz --db $DATABASE_URL --schema jimmy_test
```

### schema integrity

```bash
jimmy schema --db $DATABASE_URL
```

### migration linter

```bash
jimmy migrations lint --dir ./supabase/migrations
jimmy migrations lint --file ./db/migrations/20260508_add_users.sql
```

### transaction anomalies

```bash
jimmy anomalies --db $DATABASE_URL --tests lost-update,write-skew,read-skew,g2
```

### n+1

```bash
# from pg_stat_statements
jimmy nplusone --db $DATABASE_URL --threshold 5

# from a recorded log
jimmy nplusone --log queries.log
```

## safety

databases are precious. jimmy is paranoid by default.

- read-only postgres connections everywhere except `rls fuzz` and `anomalies`, which use a dedicated test schema
- production-name guard: refuses to run if database name contains `prod`, `production`, or `live`
- host allowlist: pass `--allow-host` once per accepted host
- transaction wrapping: every mutating probe runs in `BEGIN; ...; ROLLBACK;` unless explicitly told otherwise
- query timeout: every statement has a `statement_timeout` set
- max-rows guard: introspection queries are capped

## how the property tests work

rls fuzz, in plain english:

1. introspect the schema. find every table with rls enabled and every policy attached
2. create two synthetic tenants in a test schema (or use the schema you point it at)
3. seed each tenant with a row in every relevant table
4. for each (table, role, operation) tuple, authenticate as tenant A and try to: `SELECT` tenant B's rows, `UPDATE` them, `DELETE` them, and `INSERT` rows that claim to belong to B
5. record a deterministic history of every attempt and the outcome
6. report any case where A could touch B's data

the verdict is deterministic. the inputs (tenant counts, attempts, payloads) are generated but the check is not.

## anomaly probes

each probe runs the canonical hermitage workload at every isolation level the database supports:

- **lost update (P4)**: two transactions read the same row, both write, one wins silently
- **read skew (G-single)**: a transaction reads two rows that should be related, sees them at different points in time
- **write skew (G2-item)**: two transactions read overlapping rows, write disjoint rows, and break a database-wide invariant
- **anti-dependency cycle (G2)**: same as above but with predicates instead of items
- **phantom (A3)**: a predicate query returns a different row set when re-run because a concurrent insert committed
- **lost-update-for-update**: a control probe. runs the lost-update workload with `SELECT ... FOR UPDATE` and asserts it is prevented at every level, including read committed. proves the standard fix works on this engine

jimmy reports which anomaly is observable at which isolation level and recommends the minimum level needed to prevent it.

## migration linter rules

- `add-not-null-without-default`: adding a `NOT NULL` column to a non-empty table without a default
- `non-concurrent-index`: creating an index without `CONCURRENTLY`
- `type-rewrite`: type changes that rewrite the entire table
- `add-fk-without-not-valid`: adding a foreign key without `NOT VALID` (validates every row under a lock)
- `add-check-without-not-valid`: adding a `CHECK` without `NOT VALID`
- `add-unique-constraint`: `ADD CONSTRAINT ... UNIQUE` without `USING INDEX` (builds the index under an exclusive lock)
- `set-not-null-on-existing`: `SET NOT NULL` on an existing column (full table scan under a lock)
- `drop-column`: dropping a column that may still be in use
- `drop-table`: dropping a table
- `truncate`: `TRUNCATE` (bypasses row triggers and audit logs)
- `rename-column`: renaming a column without a transitional alias
- `rename-table`: renaming a table without a view
- `lock-timeout-missing`: a migration runs DDL but never sets `lock_timeout` (fires once per file)
- `disable-rls`: `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`

## adopting on an existing database

a mature database will have a pile of findings on day one. you do not want to
fix all of them before the first green build. record a baseline, then only fail
on findings introduced after it.

```bash
# accept today's findings
jimmy scan --db $DATABASE_URL --update-baseline --baseline .jimmy-baseline.json

# later runs only fail on NEW findings
jimmy scan --db $DATABASE_URL --baseline .jimmy-baseline.json
```

the baseline is keyed by a stable finding id (hash of category + rule + scope),
so reformatting or moving lines does not reintroduce a baselined finding. when a
baselined issue gets fixed, jimmy tells you to refresh the baseline.

### inline suppression

migration findings can be suppressed with a comment, for the cases jimmy gets
wrong or you have consciously accepted:

```sql
-- jimmy:ignore                      -- suppress every rule on the next statement
-- jimmy:ignore migration.drop-table -- suppress one rule
DROP TABLE legacy_events;

-- jimmy:ignore-file                 -- suppress the whole file (put at the top)
```

a directive attaches to the next statement (blank and comment lines in between
are fine) or to a statement on its own line as a trailing comment.

### per-category thresholds

`--fail-on` takes a bare severity or a per-category spec. categories: `rls`
(both audit and fuzz), `schema`, `migrations`, `anomalies`, `nplusone`.

```bash
# strict on rls, lenient on schema
jimmy scan --db $DATABASE_URL --fail-on "default=high,rls=medium,schema=critical"
```

## exit codes

- `0`: no findings at or above the `--fail-on` threshold (after baseline)
- `2`: findings at or above the `--fail-on` threshold (default: `high`)
- `3`: safety guard blocked execution
- `4`: could not connect or introspect

## architecture

```
src/
  db/            connection, introspection, role impersonation
  safety/        production-name guard, statement timeouts, transaction wrappers
  checks/
    rls/         static audit + property-based fuzz
    schema/      integrity scan
    migrations/  squawk-style linter
    anomalies/   hermitage probes
    nplusone/    query template grouper
  report/        markdown + json generators
  cli/           commander entry points
```

## development

```bash
npm run dev          # watch build
npm run test         # unit tests
npm run test:run     # unit tests once
npm run typecheck    # types
npm run build        # production build
```

integration tests need a real postgres. two ways to get one.

local postgres:

```bash
./scripts/setup-test-db.sh        # creates jimmy_test + the anon/authenticated roles
npm run test:integration          # defaults to postgres://localhost:5432/jimmy_test
```

throwaway docker:

```bash
docker compose -f docker-compose.test.yml up -d
JIMMY_TEST_DB=postgres://postgres:postgres@localhost:55432/jimmy_test npm run test:integration
docker compose -f docker-compose.test.yml down -v
```

the integration suite proves the real behavior, not just the pure logic: the rls
fuzz catches a `USING (true)` leak and clears a properly isolated table, and the
anomaly probes reproduce the classical postgres isolation results (write skew and
g2 observable at repeatable read, everything safe at serializable). ci runs both
on every push.

## license

mit
