/**
 * Static RLS audit. Looks at the schema and reports rls misconfigurations
 * without ever sending a SELECT against user data.
 *
 * Rules:
 *   rls.disabled          - table has no row-level security at all
 *   rls.enabled-no-policy - rls is on but no policy exists, all queries fail closed (still bad: the operator probably forgot to add policies)
 *   rls.permissive-true   - a policy whose USING/WITH CHECK is `true` or trivially true
 *   rls.role-public       - a permissive policy granted to PUBLIC
 *   rls.no-with-check     - INSERT/UPDATE/ALL policy missing WITH CHECK (rows the role inserts can violate the read policy)
 *   rls.bypass-role       - a non-system role has BYPASSRLS
 *   rls.tenant-no-filter  - policy USING clause does not reference any tenant-scoping column on the table
 */

import type { SchemaSnapshot, TableInfo, PolicyInfo } from "../../db/introspect.js";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

export interface RlsAuditOptions {
  /**
   * Column names that the auditor treats as tenant scoping markers. If a
   * policy USING clause does not reference at least one of these AND the
   * table has at least one of these columns, the policy is flagged.
   */
  tenantColumnNames?: string[];
  /** Roles excluded from BYPASSRLS warning (postgres internals). */
  systemBypassRlsRoles?: string[];
  /** Roles considered public-facing (anon, authenticated, etc). */
  publicRoles?: string[];
}

const DEFAULT_TENANT_COLUMNS = [
  "tenant_id",
  "organization_id",
  "org_id",
  "workspace_id",
  "account_id",
  "company_id",
  "user_id",
  "owner_id",
];

const DEFAULT_SYSTEM_BYPASS_RLS_ROLES = [
  "postgres",
  "supabase_admin",
  "supabase_storage_admin",
  "supabase_auth_admin",
  "supabase_replication_admin",
  // service_role bypasses RLS by design in Supabase; it is meant for trusted
  // server-side code, never the browser. Flagging it produces only noise.
  "service_role",
  "rds_superuser",
];

const DEFAULT_PUBLIC_ROLES = ["public", "anon", "authenticated"];

/**
 * Heuristic: is this USING/WITH CHECK clause trivially true?
 * Postgres normalizes `USING (true)` to `(true)`, but operators sometimes
 * write equivalent forms. We try a small set.
 */
function isTriviallyTrue(clause: string | null): boolean {
  if (clause === null) return false;
  const normalized = clause.trim().toLowerCase().replace(/\s+/g, " ");
  return (
    normalized === "true" ||
    normalized === "(true)" ||
    normalized === "1=1" ||
    normalized === "(1=1)" ||
    normalized === "(1 = 1)" ||
    normalized === "1 = 1"
  );
}

/**
 * Is this clause trivially false (a deny-all)? A `USING (false)` policy is the
 * common "service_role only" lockdown: it leaks nothing, so it must not be
 * flagged as tenant-no-filter just because it does not name a tenant column.
 */
function isTriviallyFalse(clause: string | null): boolean {
  if (clause === null) return false;
  const n = clause.trim().toLowerCase().replace(/\s+/g, " ");
  return n === "false" || n === "(false)" || n === "1=0" || n === "(1=0)" || n === "(1 = 0)" || n === "1 = 0";
}

function clauseReferencesAny(clause: string | null, columns: string[]): boolean {
  if (clause === null) return false;
  const lower = clause.toLowerCase();
  return columns.some((c) => {
    const word = c.toLowerCase();
    const re = new RegExp(`(^|[^a-z0-9_])${word}([^a-z0-9_]|$)`);
    return re.test(lower);
  });
}

function findTablePolicies(table: TableInfo, policies: PolicyInfo[]): PolicyInfo[] {
  return policies.filter((p) => p.schema === table.schema && p.table === table.name);
}

export function auditRls(snapshot: SchemaSnapshot, opts: RlsAuditOptions = {}): Finding[] {
  const tenantColumns = opts.tenantColumnNames ?? DEFAULT_TENANT_COLUMNS;
  const systemBypass = new Set(opts.systemBypassRlsRoles ?? DEFAULT_SYSTEM_BYPASS_RLS_ROLES);
  const publicRoles = new Set((opts.publicRoles ?? DEFAULT_PUBLIC_ROLES).map((r) => r.toLowerCase()));

  const findings: Finding[] = [];

  // Tables a public-facing role (anon/authenticated/public) can actually reach.
  // PostgREST only exposes a table if such a grant exists, so RLS-off on a table
  // with no public grant is a defense-in-depth gap, not a live leak.
  const publicGrantedTables = new Set(
    snapshot.grants
      .filter((g) => publicRoles.has(g.grantee.toLowerCase()))
      .map((g) => `${g.schema}.${g.table}`),
  );
  // If grants could not be introspected at all, assume reachable (fail safe).
  const grantsKnown = snapshot.grants.length > 0;

  for (const table of snapshot.tables) {
    const fqn = `${table.schema}.${table.name}`;
    const policies = findTablePolicies(table, snapshot.policies);
    const tableTenantCols = snapshot.columns
      .filter((c) => c.schema === table.schema && c.table === table.name)
      .map((c) => c.name)
      .filter((n) => tenantColumns.includes(n.toLowerCase()));

    if (!table.rlsEnabled) {
      const reachable = !grantsKnown || publicGrantedTables.has(fqn);
      // Reachable + tenant column -> critical; reachable plain -> high;
      // not reachable by a public role -> medium (defense-in-depth only).
      const severity: Severity = !reachable
        ? "medium"
        : tableTenantCols.length > 0
          ? "critical"
          : "high";
      findings.push({
        id: findingId("rls-audit", "rls.disabled", fqn),
        category: "rls-audit",
        ruleId: "rls.disabled",
        severity,
        title: `RLS disabled on ${fqn}`,
        description:
          `Table ${fqn} has row-level security disabled. ` +
          (!reachable
            ? `No public-facing role (anon/authenticated) is granted on it, so it is not reachable via PostgREST today; this is a defense-in-depth gap. Enable RLS before granting any public access.`
            : tableTenantCols.length > 0
              ? `The table has tenant-scoping columns (${tableTenantCols.join(", ")}) and is reachable by a public role, so that role reads every tenant.`
              : `It is reachable by a public role with table-level grants, which reads every row.`),
        location: { schema: table.schema, table: table.name },
        remediation: `ALTER TABLE ${fqn} ENABLE ROW LEVEL SECURITY;\nALTER TABLE ${fqn} FORCE ROW LEVEL SECURITY;\n-- then add CREATE POLICY statements scoped to your auth model`,
        evidence: { tenantColumns: tableTenantCols, estimatedRows: table.estimatedRows, publicReachable: reachable },
      });
      continue;
    }

    if (table.rlsEnabled && policies.length === 0) {
      findings.push({
        id: findingId("rls-audit", "rls.enabled-no-policy", fqn),
        category: "rls-audit",
        ruleId: "rls.enabled-no-policy",
        severity: "medium",
        title: `RLS enabled but no policy on ${fqn}`,
        description:
          `Table ${fqn} has RLS enabled with no policies. Non-superuser, non-bypass roles will read zero rows. ` +
          `If the application reads from this table, that path is broken; if it does not, this is a residue of a deletion that should be removed.`,
        location: { schema: table.schema, table: table.name },
        remediation: `-- either add the policies you intended:\n-- CREATE POLICY <name> ON ${fqn} FOR SELECT USING ( <expr> );\n-- or drop the table if it is unused`,
      });
    }

    if (!table.rlsForced && table.rlsEnabled) {
      findings.push({
        id: findingId("rls-audit", "rls.not-forced", fqn),
        category: "rls-audit",
        ruleId: "rls.not-forced",
        severity: "low",
        title: `RLS enabled but not FORCED on ${fqn}`,
        description:
          `Table ${fqn} has RLS enabled but not FORCED. The owner role bypasses RLS. ` +
          `If your application connects as the table owner, RLS is a no-op for that path.`,
        location: { schema: table.schema, table: table.name },
        remediation: `ALTER TABLE ${fqn} FORCE ROW LEVEL SECURITY;`,
      });
    }

    for (const policy of policies) {
      const policyScope = `${fqn}.${policy.name}`;

      const usingTrue = isTriviallyTrue(policy.using);
      const withCheckTrue = isTriviallyTrue(policy.withCheck);
      // A trivially-true USING clause is a read/all-access leak: critical.
      // A trivially-true WITH CHECK on an INSERT-only policy is the standard
      // "anyone may submit this form" pattern: it exposes no reads, so it is a
      // low-severity write-permissiveness note, not a critical leak.
      const insertOnlyWriteOpen = !usingTrue && withCheckTrue && policy.command === "INSERT";
      if ((usingTrue || withCheckTrue) && policy.type === "PERMISSIVE") {
        findings.push({
          id: findingId("rls-audit", "rls.permissive-true", policyScope),
          category: "rls-audit",
          ruleId: "rls.permissive-true",
          severity: insertOnlyWriteOpen ? "low" : "critical",
          title: insertOnlyWriteOpen
            ? `INSERT policy with WITH CHECK (true) on ${fqn}`
            : `Permissive policy with USING (true) on ${fqn}`,
          description:
            `Policy "${policy.name}" on ${fqn} is PERMISSIVE and ` +
            (usingTrue ? "its USING clause is true" : "its WITH CHECK clause is true") +
            (insertOnlyWriteOpen
              ? `. This is INSERT-only, so it lets the roles [${policy.roles.join(", ")}] submit any row (the standard public-form pattern) but exposes no reads. Confirm unauthenticated writes are intended.`
              : `. RLS is, in effect, off for the roles this policy applies to: [${policy.roles.join(", ")}].`),
          location: { schema: table.schema, table: table.name, role: policy.roles.join(",") },
          remediation: insertOnlyWriteOpen
            ? `-- if unauthenticated submission is intended, this is fine; otherwise add a WITH CHECK predicate`
            : `DROP POLICY "${policy.name}" ON ${fqn};\n-- replace with a tenant-scoped predicate`,
          evidence: {
            policy: policy.name,
            command: policy.command,
            using: policy.using,
            withCheck: policy.withCheck,
          },
        });
      }

      const grantsToPublic = policy.roles.some((r) => publicRoles.has(r.toLowerCase()));
      if (grantsToPublic && policy.type === "PERMISSIVE") {
        const refsTenant =
          tableTenantCols.length > 0 &&
          (clauseReferencesAny(policy.using, tableTenantCols) ||
            clauseReferencesAny(policy.withCheck, tableTenantCols));

        // A deny-all (USING (false)) policy leaks nothing, so it is not a
        // tenant-no-filter problem even though it names no tenant column.
        const denyAll = isTriviallyFalse(policy.using);

        if (tableTenantCols.length > 0 && !refsTenant && !denyAll) {
          findings.push({
            id: findingId("rls-audit", "rls.tenant-no-filter", policyScope),
            category: "rls-audit",
            ruleId: "rls.tenant-no-filter",
            severity: "high",
            title: `Public-role policy on ${fqn} does not reference a tenant column`,
            description:
              `Policy "${policy.name}" applies to public roles [${policy.roles.join(", ")}] but its predicates do not reference any of the tenant columns on this table (${tableTenantCols.join(", ")}). ` +
              `That likely means the policy passes regardless of tenant identity.`,
            location: { schema: table.schema, table: table.name, role: policy.roles.join(",") },
            evidence: {
              policy: policy.name,
              tenantColumns: tableTenantCols,
              using: policy.using,
              withCheck: policy.withCheck,
            },
          });
        }
      }

      const writeCommands = ["INSERT", "UPDATE", "ALL"];
      if (writeCommands.includes(policy.command) && !policy.withCheck) {
        const sev: Severity = grantsToPublic ? "high" : "medium";
        findings.push({
          id: findingId("rls-audit", "rls.no-with-check", policyScope),
          category: "rls-audit",
          ruleId: "rls.no-with-check",
          severity: sev,
          title: `${policy.command} policy without WITH CHECK on ${fqn}`,
          description:
            `Policy "${policy.name}" governs writes (${policy.command}) on ${fqn} but has no WITH CHECK clause. ` +
            `An authorized writer can insert or update rows that violate the read predicate, leaving rows visible to no one or to the wrong tenant.`,
          location: { schema: table.schema, table: table.name },
          remediation: `-- add a matching WITH CHECK clause that mirrors the USING predicate`,
          evidence: { policy: policy.name, command: policy.command, using: policy.using },
        });
      }
    }
  }

  for (const role of snapshot.roles) {
    if (role.canBypassRls && !systemBypass.has(role.name)) {
      findings.push({
        id: findingId("rls-audit", "rls.bypass-role", role.name),
        category: "rls-audit",
        ruleId: "rls.bypass-role",
        severity: "high",
        title: `Role ${role.name} can bypass RLS`,
        description:
          `Role ${role.name} has BYPASSRLS. If the application connects as this role, RLS is silently disabled for every query. ` +
          `Confirm this role is only used for migrations or admin tooling, never for request-time queries.`,
        location: { role: role.name },
        remediation: `ALTER ROLE ${role.name} NOBYPASSRLS;`,
        evidence: {
          isSuperuser: role.isSuperuser,
          canLogin: role.canLogin,
        },
      });
    }
  }

  return findings;
}

export const _internal = {
  isTriviallyTrue,
  clauseReferencesAny,
  DEFAULT_TENANT_COLUMNS,
  DEFAULT_SYSTEM_BYPASS_RLS_ROLES,
  DEFAULT_PUBLIC_ROLES,
};
