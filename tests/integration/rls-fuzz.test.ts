import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import {
  databaseReachable,
  ensureSupabaseRoles,
  freshSchema,
  rawClient,
  testConnection,
} from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { fuzzRls } from "../../src/checks/rls/fuzz.js";

const SCHEMA = "jimmy_fuzz_it";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

maybe("rls fuzz (integration)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await ensureSupabaseRoles(admin);
    await freshSchema(admin, SCHEMA);

    // GOOD: tenant isolation via jwt sub claim, both USING and WITH CHECK
    await admin.query(`
      CREATE TABLE ${SCHEMA}.documents_good (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id uuid NOT NULL,
        body text
      )
    `);
    await admin.query(`ALTER TABLE ${SCHEMA}.documents_good ENABLE ROW LEVEL SECURITY`);
    await admin.query(`ALTER TABLE ${SCHEMA}.documents_good FORCE ROW LEVEL SECURITY`);
    await admin.query(`
      CREATE POLICY tenant_isolation ON ${SCHEMA}.documents_good
        FOR ALL
        TO authenticated
        USING (tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
        WITH CHECK (tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
    `);

    // BROKEN: USING (true) leaks every tenant to every authenticated user
    await admin.query(`
      CREATE TABLE ${SCHEMA}.documents_broken (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id uuid NOT NULL,
        body text
      )
    `);
    await admin.query(`ALTER TABLE ${SCHEMA}.documents_broken ENABLE ROW LEVEL SECURITY`);
    await admin.query(`ALTER TABLE ${SCHEMA}.documents_broken FORCE ROW LEVEL SECURITY`);
    await admin.query(`
      CREATE POLICY wide_open ON ${SCHEMA}.documents_broken
        FOR ALL
        TO authenticated
        USING (true)
        WITH CHECK (true)
    `);

    // HARD CASE: NOT NULL enum column + FK to a parent we never seed.
    // Exercises enum-value generation and FK suppression during seeding.
    await admin.query(`CREATE TYPE ${SCHEMA}.doc_status AS ENUM ('draft', 'published')`);
    await admin.query(`CREATE TABLE ${SCHEMA}.owners (id uuid PRIMARY KEY DEFAULT gen_random_uuid())`);
    await admin.query(`
      CREATE TABLE ${SCHEMA}.documents_enum (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id uuid NOT NULL,
        owner_id uuid NOT NULL REFERENCES ${SCHEMA}.owners(id),
        status ${SCHEMA}.doc_status NOT NULL,
        body text
      )
    `);
    await admin.query(`ALTER TABLE ${SCHEMA}.documents_enum ENABLE ROW LEVEL SECURITY`);
    await admin.query(`ALTER TABLE ${SCHEMA}.documents_enum FORCE ROW LEVEL SECURITY`);
    await admin.query(`
      CREATE POLICY tenant_isolation ON ${SCHEMA}.documents_enum
        FOR ALL TO authenticated
        USING (tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
        WITH CHECK (tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
    `);

    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${SCHEMA} TO authenticated`);
    await admin.query(`GRANT SELECT ON ALL TABLES IN SCHEMA ${SCHEMA} TO anon`);
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
      await admin.end();
    }
  });

  it("detects tenant leakage on the USING(true) table but not the isolated one", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const result = await fuzzRls(conn, snapshot, { roles: ["authenticated"] });

      const brokenFindings = result.findings.filter((f) => f.location.table === "documents_broken");
      const goodFindings = result.findings.filter((f) => f.location.table === "documents_good");

      // The broken table should leak across at least SELECT.
      expect(brokenFindings.length).toBeGreaterThan(0);
      expect(brokenFindings.every((f) => f.severity === "critical")).toBe(true);
      expect(brokenFindings.some((f) => f.ruleId === "rls.fuzz.select")).toBe(true);

      // The isolated table must not leak.
      expect(goodFindings).toHaveLength(0);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("seeds and probes a table with a NOT NULL enum and an FK to an unseeded parent (not skipped)", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const result = await fuzzRls(conn, snapshot, { roles: ["authenticated"] });

      // It must NOT appear in the skipped list (enum + FK handled).
      expect(result.skipped.find((s) => s.table.endsWith("documents_enum"))).toBeUndefined();
      // It must actually get probed.
      const probed = result.history.filter((h) => h.table.endsWith("documents_enum"));
      expect(probed.length).toBeGreaterThan(0);
      // And it is properly isolated, so no leak findings.
      expect(result.findings.filter((f) => f.location.table === "documents_enum")).toHaveLength(0);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("leaves no jimmy probe rows behind (everything rolled back)", async () => {
    const goodCount = await admin.query(`SELECT count(*)::int AS c FROM ${SCHEMA}.documents_good`);
    const brokenCount = await admin.query(`SELECT count(*)::int AS c FROM ${SCHEMA}.documents_broken`);
    expect((goodCount.rows[0] as { c: number }).c).toBe(0);
    expect((brokenCount.rows[0] as { c: number }).c).toBe(0);
  });
});
