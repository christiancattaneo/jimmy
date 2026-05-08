# jimmy

pries open the database the application thinks is locked.

a crowbar tests the front door. jimmy tests the **basement** the front door is hiding. it pokes at the gaps the other tools miss: row-level security, multi-tenant isolation, transactional anomalies, schema integrity, and migration safety.

inspired by jepsen and elle, but pointed one layer up: at your application's use of the database, not the database engine itself.

## what it finds

slopometer, pinata, whackamole, crowbar, orion all touch the database, but only at the edges: injection at the query string, pool exhaustion, capacity. jimmy covers the rest.

- **rls bypass**: tables with rls disabled, permissive `USING (true)` policies, columns reachable as the anon role, policies that depend on `auth.uid()` but are reachable unauthenticated
- **multi-tenant leakage**: seed two tenants, authenticate as A, prove A cannot read, update, or delete any of B's rows across every table. mechanically enumerated from the schema
- **transaction anomalies**: hermitage-style probes for lost update, write skew, read skew, and G2 (anti-dependency cycles). run at every isolation level and assert the database actually behaves the way the app assumes
- **schema integrity**: missing foreign keys, weak `NOT NULL`, missing `UNIQUE`, missing `CHECK`, soft-delete columns referenced inconsistently, nullable columns the app code assumes are non-null
- **migration safety**: squawk-style linter for dangerous DDL: `ALTER TABLE ... ADD COLUMN ... NOT NULL` without default, non-`CONCURRENTLY` index creation, type rewrites, dropping columns still referenced
- **n+1 detection**: groups query templates from `pg_stat_statements` or a recorded log, flags repeated executions per request

## install

```bash
npm install
npm run build
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
# static introspection only (read-only, instant)
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

jimmy reports which anomaly is observable at which isolation level and recommends the minimum level needed to prevent it.

## migration linter rules

- `add-not-null-without-default`: adding a `NOT NULL` column to a non-empty table without a default
- `non-concurrent-index`: creating an index without `CONCURRENTLY`
- `type-rewrite`: type changes that rewrite the entire table
- `drop-column`: dropping a column that may still be in use
- `drop-table`: dropping a table
- `rename-column`: renaming a column without a transitional alias
- `rename-table`: renaming a table without a view
- `lock-timeout-missing`: DDL without a `lock_timeout` set
- `disable-rls`: `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`

## exit codes

- `0`: no findings at or above `--fail-on` severity
- `2`: findings at or above `--fail-on` severity (default: `high`)
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

integration tests need a real postgres. point `JIMMY_TEST_DB` at a throwaway database:

```bash
JIMMY_TEST_DB=postgres://localhost:5432/jimmy_test npm run test:integration
```

## license

mit
