import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, ensureSupabaseRoles, freshSchema, rawClient, testConnection } from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { auditRls } from "../../src/checks/rls/audit.js";

const SCHEMA = "jimmy_audit_it";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

maybe("rls audit (integration)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await ensureSupabaseRoles(admin);
    await freshSchema(admin, SCHEMA);

    // rls disabled, has tenant column -> critical
    await admin.query(`CREATE TABLE ${SCHEMA}.no_rls (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)`);

    // rls enabled, USING(true) -> critical
    await admin.query(`CREATE TABLE ${SCHEMA}.permissive (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)`);
    await admin.query(`ALTER TABLE ${SCHEMA}.permissive ENABLE ROW LEVEL SECURITY`);
    await admin.query(`CREATE POLICY p ON ${SCHEMA}.permissive FOR SELECT TO authenticated USING (true)`);

    // properly isolated -> clean
    await admin.query(`CREATE TABLE ${SCHEMA}.isolated (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)`);
    await admin.query(`ALTER TABLE ${SCHEMA}.isolated ENABLE ROW LEVEL SECURITY`);
    await admin.query(`ALTER TABLE ${SCHEMA}.isolated FORCE ROW LEVEL SECURITY`);
    await admin.query(`
      CREATE POLICY p ON ${SCHEMA}.isolated FOR ALL TO authenticated
        USING (tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
        WITH CHECK (tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
    `);
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
      await admin.end();
    }
  });

  it("flags the disabled and permissive tables, clears the isolated one", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const findings = auditRls(snapshot);

      const byTable = (t: string) => findings.filter((f) => f.location.table === t);

      expect(byTable("no_rls").some((f) => f.ruleId === "rls.disabled" && f.severity === "critical")).toBe(true);
      expect(byTable("permissive").some((f) => f.ruleId === "rls.permissive-true" && f.severity === "critical")).toBe(true);

      // The isolated table is correct; it may still earn an info/low note but no high+.
      const isolatedHigh = byTable("isolated").filter((f) => f.severity === "high" || f.severity === "critical");
      expect(isolatedHigh).toHaveLength(0);
    } finally {
      await conn.end();
    }
  }, 60_000);
});
