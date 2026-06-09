/**
 * Graded corpus validation. Three labeled database setups built from
 * documented, real-world Postgres/Supabase patterns, loaded into a live
 * database and graded by jimmy. The point is falsifiable calibration: a
 * known-good schema must come back clean, a known-bad one must light up with
 * criticals, and a mediocre one must sit in between. If jimmy ever drifts, one
 * of these three assertions breaks.
 *
 * Patterns are sourced from:
 *   - Supabase RLS docs and the "USING (true)" / public-grant footguns
 *     (https://supabase.com/docs/guides/database/postgres/row-level-security)
 *   - The SECURITY DEFINER + mutable search_path privilege-escalation class
 *     (PostgreSQL CVE-2018-1058; "Writing SECURITY DEFINER Functions Safely",
 *     PostgreSQL docs)
 *   - OWASP storage of unsalted/plaintext credentials and sensitive PII at rest
 *   - Standard relational-integrity guidance: every table a primary key, every
 *     foreign key a constraint and a covering index.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, ensureSupabaseRoles, freshSchema, rawClient, testConnection } from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { auditRls } from "../../src/checks/rls/audit.js";
import { auditSchema } from "../../src/checks/schema/audit.js";
import { auditPii } from "../../src/checks/pii/audit.js";
import { auditRpc } from "../../src/checks/rls/rpc.js";
import type { Finding, Severity } from "../../src/report/findings.js";

const GOOD = "corpus_good";
const MEDIUM = "corpus_medium";
const BAD = "corpus_bad";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

// JWT-subject expression used in place of auth.uid() so fixtures need no auth schema.
const SUB = `(current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid`;

function runAllChecks(snapshot: Parameters<typeof auditRls>[0]): Finding[] {
  return [
    ...auditRls(snapshot),
    ...auditSchema(snapshot),
    ...auditPii(snapshot),
    ...auditRpc(snapshot),
  ].filter(
    // rls.bypass-role is a global role property (the local superuser that runs
    // the test owns BYPASSRLS), not a property of any one fixture schema. It
    // fires identically for good/medium/bad, so it cannot discriminate between
    // them; exclude it from per-schema grading. In production the app role is
    // NOBYPASSRLS and this finding would not appear.
    (f) => f.ruleId !== "rls.bypass-role",
  );
}

function countBy(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

maybe("graded corpus validation (integration)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await ensureSupabaseRoles(admin);

    // ---------------------------------------------------------------------
    // GOOD: textbook multi-tenant SaaS. Every table has a PK, every FK has a
    // constraint and a covering index, RLS is on AND forced, and every policy
    // is tenant-scoped with both USING and WITH CHECK. Passwords are hashed.
    // No SECURITY DEFINER functions, no plaintext secrets.
    // ---------------------------------------------------------------------
    await freshSchema(admin, GOOD);
    await admin.query(`
      CREATE TABLE ${GOOD}.accounts (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        name text NOT NULL,
        slug text NOT NULL UNIQUE
      );
      CREATE TABLE ${GOOD}.users (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        account_id uuid NOT NULL REFERENCES ${GOOD}.accounts(id) ON DELETE RESTRICT,
        email text NOT NULL UNIQUE,
        password_hash text NOT NULL
      );
      CREATE INDEX ON ${GOOD}.users (account_id);
      CREATE TABLE ${GOOD}.documents (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        account_id uuid NOT NULL REFERENCES ${GOOD}.accounts(id) ON DELETE RESTRICT,
        owner_id uuid NOT NULL REFERENCES ${GOOD}.users(id) ON DELETE RESTRICT,
        title text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX ON ${GOOD}.documents (account_id);
      CREATE INDEX ON ${GOOD}.documents (owner_id);
    `);
    for (const t of ["accounts", "users", "documents"]) {
      await admin.query(`ALTER TABLE ${GOOD}.${t} ENABLE ROW LEVEL SECURITY`);
      await admin.query(`ALTER TABLE ${GOOD}.${t} FORCE ROW LEVEL SECURITY`);
    }
    await admin.query(`
      CREATE POLICY acct_isolation ON ${GOOD}.accounts FOR ALL TO authenticated
        USING (id = ${SUB}) WITH CHECK (id = ${SUB});
      CREATE POLICY users_isolation ON ${GOOD}.users FOR ALL TO authenticated
        USING (account_id = ${SUB}) WITH CHECK (account_id = ${SUB});
      CREATE POLICY docs_isolation ON ${GOOD}.documents FOR ALL TO authenticated
        USING (account_id = ${SUB}) WITH CHECK (account_id = ${SUB});
    `);

    // ---------------------------------------------------------------------
    // MEDIUM: it works and isolates tenants, but it has rough edges that are
    // medium by design: a real FK with no covering index, a cascade from a
    // tenant-shaped table, a required-looking timestamp left nullable, and an
    // RLS-enabled table with no policy (a broken/orphaned read path). No
    // criticals, no highs.
    // ---------------------------------------------------------------------
    await freshSchema(admin, MEDIUM);
    await admin.query(`
      CREATE TABLE ${MEDIUM}.accounts (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        name text NOT NULL
      );
      CREATE TABLE ${MEDIUM}.notes (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        account_id uuid NOT NULL REFERENCES ${MEDIUM}.accounts(id) ON DELETE CASCADE,
        body text NOT NULL,
        created_at timestamptz
      );
      -- intentionally NO index on notes.account_id  -> schema.fk-no-index (medium)
      -- ON DELETE CASCADE to accounts                -> schema.tenant-cascade (medium)
      -- created_at nullable                          -> schema.weak-not-null (medium)
      CREATE TABLE ${MEDIUM}.audit_log (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        account_id uuid NOT NULL REFERENCES ${MEDIUM}.accounts(id) ON DELETE RESTRICT,
        event text NOT NULL
      );
      CREATE INDEX ON ${MEDIUM}.audit_log (account_id);
    `);
    for (const t of ["accounts", "notes", "audit_log"]) {
      await admin.query(`ALTER TABLE ${MEDIUM}.${t} ENABLE ROW LEVEL SECURITY`);
      await admin.query(`ALTER TABLE ${MEDIUM}.${t} FORCE ROW LEVEL SECURITY`);
    }
    await admin.query(`
      CREATE POLICY acct_isolation ON ${MEDIUM}.accounts FOR ALL TO authenticated
        USING (id = ${SUB}) WITH CHECK (id = ${SUB});
      CREATE POLICY notes_isolation ON ${MEDIUM}.notes FOR ALL TO authenticated
        USING (account_id = ${SUB}) WITH CHECK (account_id = ${SUB});
      -- audit_log: RLS enabled, NO policy -> rls.enabled-no-policy (medium)
    `);

    // ---------------------------------------------------------------------
    // BAD: the greatest hits. RLS off on a PII table reachable by anon; a
    // SELECT policy with USING (true); a plaintext password and api key; a
    // SECURITY DEFINER function callable by public with no pinned search_path;
    // and a table with no primary key.
    // ---------------------------------------------------------------------
    await freshSchema(admin, BAD);
    await admin.query(`
      -- RLS OFF on a table with a tenant column, granted to anon -> rls.disabled (critical)
      CREATE TABLE ${BAD}.leaked_profiles (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL,
        ssn text NOT NULL,            -- pii.plaintext-pii (medium)
        password text NOT NULL,       -- pii.plaintext-password (critical)
        stripe_api_key text           -- pii.plaintext-secret (high)
      );
      GRANT SELECT, INSERT ON ${BAD}.leaked_profiles TO anon, authenticated;

      -- RLS on but a SELECT policy USING (true) -> rls.permissive-true (critical)
      CREATE TABLE ${BAD}.wide_open (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        secret_note text NOT NULL
      );
      ALTER TABLE ${BAD}.wide_open ENABLE ROW LEVEL SECURITY;
      GRANT SELECT ON ${BAD}.wide_open TO anon;
      CREATE POLICY anyone_reads ON ${BAD}.wide_open FOR SELECT TO anon USING (true);

      -- no primary key -> schema.no-primary-key (high)
      CREATE TABLE ${BAD}.events_no_pk (
        payload jsonb NOT NULL
      );
    `);
    // SECURITY DEFINER, public-executable, mutable search_path:
    //   rpc.definer-public (high) + rpc.definer-search-path (high)
    await admin.query(`
      CREATE OR REPLACE FUNCTION ${BAD}.escalate(target uuid)
      RETURNS SETOF ${BAD}.leaked_profiles
      LANGUAGE sql SECURITY DEFINER AS $fn$
        SELECT * FROM ${BAD}.leaked_profiles WHERE user_id = target;
      $fn$;
    `);
  }, 120_000);

  afterAll(async () => {
    if (admin) {
      for (const s of [GOOD, MEDIUM, BAD]) {
        await admin.query(`DROP SCHEMA IF EXISTS ${s} CASCADE`);
      }
      await admin.end();
    }
  });

  it("grades the GOOD schema clean: zero medium/high/critical", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [GOOD] }));
      const findings = runAllChecks(snapshot);
      const c = countBy(findings);
      const blocking = findings.filter((f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium");
      // Surface anything unexpected in the failure message.
      expect(blocking.map((f) => `${f.severity}:${f.ruleId}:${f.location.table ?? f.location.role ?? ""}`)).toEqual([]);
      expect(c.critical).toBe(0);
      expect(c.high).toBe(0);
      expect(c.medium).toBe(0);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("grades the MEDIUM schema as rough but not dangerous: some medium, zero high/critical", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [MEDIUM] }));
      const findings = runAllChecks(snapshot);
      const c = countBy(findings);
      const rules = new Set(findings.map((f) => f.ruleId));

      expect(c.critical).toBe(0);
      expect(c.high).toBe(0);
      expect(c.medium).toBeGreaterThanOrEqual(2);
      // The specific rough edges we planted.
      expect(rules.has("schema.fk-no-index")).toBe(true);
      expect(rules.has("schema.tenant-cascade")).toBe(true);
      expect(rules.has("rls.enabled-no-policy")).toBe(true);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("grades the BAD schema as dangerous: multiple criticals across categories", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [BAD] }));
      const findings = runAllChecks(snapshot);
      const c = countBy(findings);
      const byRule = (id: string) => findings.filter((f) => f.ruleId === id);

      expect(c.critical).toBeGreaterThanOrEqual(3);

      // RLS off on a tenant + anon-granted table is a live cross-tenant leak.
      expect(byRule("rls.disabled").some((f) => f.severity === "critical" && f.location.table === "leaked_profiles")).toBe(true);
      // USING (true) read policy.
      expect(byRule("rls.permissive-true").some((f) => f.severity === "critical")).toBe(true);
      // Plaintext password.
      expect(byRule("pii.plaintext-password").some((f) => f.severity === "critical")).toBe(true);
      // Plaintext secret (high) and the definer hazards (high).
      expect(byRule("pii.plaintext-secret").length).toBeGreaterThanOrEqual(1);
      expect(byRule("rpc.definer-public").length).toBeGreaterThanOrEqual(1);
      expect(byRule("rpc.definer-search-path").length).toBeGreaterThanOrEqual(1);
      // Missing primary key.
      expect(byRule("schema.no-primary-key").some((f) => f.location.table === "events_no_pk")).toBe(true);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("orders the three setups by danger: bad > medium > good", async () => {
    const conn = await testConnection();
    try {
      const score = async (schema: string): Promise<number> => {
        const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [schema] }));
        const f = runAllChecks(snapshot);
        const w: Record<Severity, number> = { critical: 100, high: 10, medium: 1, low: 0, info: 0 };
        return f.reduce((s, x) => s + w[x.severity], 0);
      };
      const good = await score(GOOD);
      const medium = await score(MEDIUM);
      const bad = await score(BAD);
      expect(good).toBeLessThan(medium);
      expect(medium).toBeLessThan(bad);
    } finally {
      await conn.end();
    }
  }, 60_000);
});
