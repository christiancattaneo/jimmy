/**
 * Rule catalog. One terse entry per rule id: what it means, why it matters, and
 * how to fix it. Powers `jimmy explain <ruleId>` and serves as the canonical
 * rule reference. Kept deliberately short and concrete.
 */

import type { Severity } from "./findings.js";

export interface RuleDoc {
  id: string;
  severity: Severity;
  summary: string;
  why: string;
  fix: string;
}

export const CATALOG: RuleDoc[] = [
  // row-level security
  {
    id: "rls.disabled",
    severity: "high",
    summary: "Table has row-level security disabled.",
    why: "A public role (anon/authenticated) granted on it reads every row, regardless of tenant. Severity is reachability-aware: critical with a tenant column and a public grant, high if reachable, medium if no public role can reach it (defense-in-depth gap only).",
    fix: "ALTER TABLE t ENABLE ROW LEVEL SECURITY; ALTER TABLE t FORCE ROW LEVEL SECURITY; then add scoped policies.",
  },
  {
    id: "rls.enabled-no-policy",
    severity: "medium",
    summary: "RLS is on but the table has no policy.",
    why: "Non-privileged roles read zero rows. Either the app path is broken or this is residue of a deletion.",
    fix: "Add the intended policies, or drop the table if it is unused.",
  },
  {
    id: "rls.not-forced",
    severity: "low",
    summary: "RLS enabled but not FORCED.",
    why: "The table owner bypasses RLS. If the app connects as the owner, RLS is a no-op for that path.",
    fix: "ALTER TABLE t FORCE ROW LEVEL SECURITY;",
  },
  {
    id: "rls.permissive-true",
    severity: "critical",
    summary: "A permissive policy whose predicate is trivially true.",
    why: "USING (true) (or WITH CHECK (true)) means RLS is effectively off for the roles it applies to.",
    fix: "Drop the policy and replace it with a tenant- or owner-scoped predicate.",
  },
  {
    id: "rls.tenant-no-filter",
    severity: "high",
    summary: "A public-role policy that ignores the table's tenant column.",
    why: "The predicate passes regardless of tenant identity, so the policy does not isolate tenants.",
    fix: "Reference the tenant column, e.g. USING ( tenant_id = (auth.jwt() ->> 'sub')::uuid ).",
  },
  {
    id: "rls.no-with-check",
    severity: "medium",
    summary: "A write policy (INSERT/UPDATE/ALL) with no WITH CHECK.",
    why: "An authorized writer can insert or update rows that violate the read predicate, including rows for another tenant.",
    fix: "Add a WITH CHECK clause mirroring the USING predicate.",
  },
  {
    id: "rls.bypass-role",
    severity: "high",
    summary: "A non-system role can bypass RLS.",
    why: "If the app connects as a BYPASSRLS role, RLS is silently disabled for every query.",
    fix: "ALTER ROLE r NOBYPASSRLS; reserve bypass for migrations/admin tooling only.",
  },
  // rpc
  {
    id: "rpc.definer-public",
    severity: "high",
    summary: "A SECURITY DEFINER function callable by anon/authenticated.",
    why: "It runs as its owner, bypassing the caller's RLS. The single most common RLS bypass in Supabase.",
    fix: "Re-check auth.uid()/auth.jwt() inside the function, or REVOKE EXECUTE from public roles.",
  },
  {
    id: "rpc.definer-search-path",
    severity: "medium",
    summary: "A SECURITY DEFINER function with no pinned search_path.",
    why: "A caller who can create objects on the path can shadow a function the body calls and run it as the owner.",
    fix: "ALTER FUNCTION f SET search_path = ''; and fully-qualify every object reference.",
  },
  // storage
  {
    id: "storage.public-bucket",
    severity: "medium",
    summary: "A Supabase storage bucket is public.",
    why: "Every object is readable by anyone with the URL, no auth. Fine for avatars, dangerous for user data.",
    fix: "Make the bucket private and serve via signed URLs if it holds anything user-scoped.",
  },
  {
    id: "storage.objects-no-rls",
    severity: "high",
    summary: "RLS is disabled on storage.objects.",
    why: "Any role with grants can list and read every object in every bucket, ignoring the public flag.",
    fix: "ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY; add bucket/owner-scoped policies.",
  },
  {
    id: "storage.permissive-policy",
    severity: "high",
    summary: "A permissive storage.objects policy with USING(true) for public roles.",
    why: "Those roles can touch objects across all buckets.",
    fix: "Scope by bucket_id and owner, e.g. USING ( bucket_id = 'x' AND owner = auth.uid() ).",
  },
  // realtime
  {
    id: "realtime.broadcast-no-rls",
    severity: "high",
    summary: "A table broadcast by realtime has RLS disabled.",
    why: "Every insert/update/delete is streamed to subscribers with no per-row filtering. A quiet leak.",
    fix: "Enable and force RLS, or remove the table from the supabase_realtime publication.",
  },
  // cron
  {
    id: "cron.scheduled-job",
    severity: "info",
    summary: "A pg_cron job runs automatically as a role with no request context.",
    why: "auth.uid() is null in a cron job, so RLS that depends on it is bypassed by design.",
    fix: "Confirm the job is intended and runs with the minimum privileges; avoid DML as a superuser.",
  },
  // schema
  {
    id: "schema.no-primary-key",
    severity: "high",
    summary: "A table has no primary key.",
    why: "Replication, ORMs that assume identity, and CDC tools break or misbehave on tables without one.",
    fix: "ALTER TABLE t ADD PRIMARY KEY (id);",
  },
  {
    id: "schema.missing-fk",
    severity: "medium",
    summary: "An _id-shaped column with no foreign-key constraint.",
    why: "App-side referential checks drift; the database is the only place the guarantee survives a deploy.",
    fix: "Add the FK constraint if a relationship was intended.",
  },
  {
    id: "schema.fk-no-index",
    severity: "medium",
    summary: "A foreign-key-shaped column with no index.",
    why: "Cascading deletes scan the table sequentially; joins fall back to nested loops.",
    fix: "CREATE INDEX CONCURRENTLY ON t (col);",
  },
  {
    id: "schema.weak-not-null",
    severity: "high",
    summary: "A nullable column whose name implies it is required.",
    why: "Code that relies on the column being non-null sporadically hits undefined behavior.",
    fix: "Backfill, then ALTER TABLE t ALTER COLUMN col SET NOT NULL.",
  },
  // pii
  {
    id: "pii.plaintext-password",
    severity: "critical",
    summary: "A password column stored as plaintext.",
    why: "Passwords must be hashed; a breach exposes every credential directly.",
    fix: "Hash with bcrypt or argon2 and store the digest; never the password.",
  },
  {
    id: "pii.plaintext-secret",
    severity: "high",
    summary: "Secret material (api key, token, private key) in a plaintext column.",
    why: "A read of the row, a backup, or a log leaks live credentials.",
    fix: "Move to Vault or an encrypted column; rotate anything already stored.",
  },
  {
    id: "pii.plaintext-pii",
    severity: "medium",
    summary: "High-sensitivity PII (ssn, card number, cvv) in plaintext.",
    why: "Regulatory exposure and a juicy breach target.",
    fix: "Use column-level encryption; do not store cvv at all.",
  },
  // anomalies (one entry; the rule ids are anomaly.<name>)
  {
    id: "anomaly.lost-update",
    severity: "high",
    summary: "Two concurrent read-modify-write cycles silently overwrite each other.",
    why: "One update is lost with no error. Common in counters and balances.",
    fix: "Use at least REPEATABLE READ, or SELECT ... FOR UPDATE around the read.",
  },
  {
    id: "anomaly.write-skew",
    severity: "high",
    summary: "Two transactions read overlapping rows, write disjoint rows, and break an invariant.",
    why: "Snapshot isolation (REPEATABLE READ) allows it; only SERIALIZABLE prevents it.",
    fix: "Use SERIALIZABLE for the workload, or lock the predicate explicitly.",
  },
  // migrations (representative; all share the do-it-in-two-steps shape)
  {
    id: "migration.disable-rls",
    severity: "critical",
    summary: "ALTER TABLE ... DISABLE ROW LEVEL SECURITY in a migration.",
    why: "Removes tenant isolation. If intentional, document it; otherwise it is a backdoor.",
    fix: "Remove it, or scope the change and re-enable RLS in the same migration.",
  },
  {
    id: "migration.non-concurrent-index",
    severity: "high",
    summary: "CREATE INDEX without CONCURRENTLY.",
    why: "Takes ACCESS EXCLUSIVE and stalls every write until the build finishes.",
    fix: "CREATE INDEX CONCURRENTLY, in its own migration (it cannot run in a transaction).",
  },
  {
    id: "migration.add-not-null-without-default",
    severity: "high",
    summary: "ADD COLUMN ... NOT NULL with no default.",
    why: "Fails on a non-empty table; on old Postgres it rewrites the whole table.",
    fix: "Add with a default, or backfill in two steps then SET NOT NULL.",
  },
];

const BY_ID = new Map(CATALOG.map((r) => [r.id, r]));

/** Look up a rule by exact id, or by the closest family prefix. */
export function explainRule(ruleId: string): RuleDoc | undefined {
  const exact = BY_ID.get(ruleId);
  if (exact) return exact;
  // fuzz rules collapse to one explanation
  if (ruleId.startsWith("rls.fuzz")) {
    return {
      id: "rls.fuzz.*",
      severity: "critical",
      summary: "A tenant could read/update/delete/insert another tenant's row.",
      why: "The policy does not isolate tenants for the probed role: a real cross-tenant data leak.",
      fix: "Audit the policy USING/WITH CHECK and confirm it filters on the tenant column for that role.",
    };
  }
  // any other migration.* shares the safe-migration message
  if (ruleId.startsWith("migration.")) {
    return {
      id: ruleId,
      severity: "medium",
      summary: "A potentially unsafe DDL pattern in a migration.",
      why: "Many DDL statements take heavy locks or break in-flight deploys.",
      fix: "Prefer online, backwards-compatible variants (NOT VALID + VALIDATE, CONCURRENTLY, two-phase renames).",
    };
  }
  return undefined;
}

export function listRules(): RuleDoc[] {
  return [...CATALOG].sort((a, b) => a.id.localeCompare(b.id));
}
