# Changelog

## 0.1.0

First release. jimmy pries open the database the application thinks is locked.

Checks:

- **rls audit**: rls disabled, permissive `USING (true)`, missing `WITH CHECK`, tenant-no-filter, bypass roles, rls not forced
- **rls fuzz**: seeds two adversarial near-collision tenants and proves the first cannot read, update, delete, or insert against the second across every table, role, and operation
- **rpc audit**: `SECURITY DEFINER` functions callable by anon/authenticated, and definer functions without a pinned `search_path`
- **storage**: public buckets, no size limit, `storage.objects` rls disabled, permissive storage policies
- **realtime**: tables broadcast with rls disabled
- **pg_cron**: privileged scheduled jobs that bypass rls
- **schema integrity**: missing primary key, missing foreign key, fk with no index, weak `NOT NULL`, tenant cascade
- **secrets at rest**: plaintext password, secret, and high-sensitivity PII columns
- **index coverage**: EXPLAIN-based sequential-scan detection on tenant/fk lookups
- **migrations**: 18 squawk-style lock-hazard and dangerous-DDL rules, plus custom rules from config
- **anomalies**: lost update, read skew, write skew, g2-item, g2-predicate, phantom, and a `FOR UPDATE` control, at every isolation level, with a recommended minimum level
- **n+1**: from `pg_stat_statements`, a query log, or a request-tagged trace (per-request grouping)
- **schema regression**: `snapshot` then `regress` to catch a migration that weakens the schema
- **prisma cross-check**: drift and nullability mismatch against a `schema.prisma`
- **suggest**: deterministic schema-driven proposal of the highest-value checks to run

Production:

- read-only by default; refuses production-named databases; statement, lock, and idle timeouts on every connection; bounded probe volume
- proven not to be an injection vector against itself (adversarial canary test with hostile identifiers)
- baselines, per-category `--fail-on`, inline `-- jimmy:ignore`, `jimmy.config.json`, `--redact`, `--quiet`
- reports as markdown (grouped, with a table of contents), json, sarif, and html; published json schema
- GitHub Action, Dockerfile, Homebrew formula

Tested: 225 unit + 16 integration. pinata A (95/100), zero npm vulnerabilities.
