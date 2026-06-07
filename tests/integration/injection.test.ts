import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, ensureSupabaseRoles, freshSchema, rawClient, testConnection } from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { auditRls } from "../../src/checks/rls/audit.js";
import { fuzzRls } from "../../src/checks/rls/fuzz.js";

/**
 * Adversarial: jimmy reads identifiers from the database and builds SQL from
 * them. A hostile table/column/enum name must NOT turn jimmy into an injection
 * vector against itself. We plant a canary table and assert it survives a full
 * introspect + audit + fuzz against a schema full of SQL-injection identifiers.
 */

const SCHEMA = "jimmy_evil_it";
// real table name after un-escaping: ev"il; DROP TABLE <schema>.canary; --
const EVIL_TABLE = `ev"il; DROP TABLE ${SCHEMA}.canary; --`;
// real column name: c"); DROP TABLE <schema>.canary; --
const EVIL_COL = `c"); DROP TABLE ${SCHEMA}.canary; --`;

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

function q(id: string): string {
  return `"${id.replace(/"/g, '""')}"`;
}

maybe("sql-injection hardening (adversarial)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await ensureSupabaseRoles(admin);
    await freshSchema(admin, SCHEMA);

    // canary: if jimmy ever executes an injected statement, this disappears.
    await admin.query(`CREATE TABLE ${SCHEMA}.canary (id int primary key)`);
    await admin.query(`INSERT INTO ${SCHEMA}.canary VALUES (1)`);

    // a hostile enum type name
    await admin.query(`CREATE TYPE ${SCHEMA}.${q(`st"; DROP TABLE ${SCHEMA}.canary; --`)} AS ENUM ('a','b')`);

    // a table + column with injection payloads in their names, RLS on with a
    // permissive policy so the auditor and fuzzer both engage it.
    await admin.query(
      `CREATE TABLE ${SCHEMA}.${q(EVIL_TABLE)} (
         id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
         tenant_id uuid NOT NULL,
         ${q(EVIL_COL)} text,
         status ${SCHEMA}.${q(`st"; DROP TABLE ${SCHEMA}.canary; --`)} NOT NULL DEFAULT 'a'
       )`,
    );
    await admin.query(`ALTER TABLE ${SCHEMA}.${q(EVIL_TABLE)} ENABLE ROW LEVEL SECURITY`);
    await admin.query(`ALTER TABLE ${SCHEMA}.${q(EVIL_TABLE)} FORCE ROW LEVEL SECURITY`);
    await admin.query(
      `CREATE POLICY wide ON ${SCHEMA}.${q(EVIL_TABLE)} FOR ALL TO authenticated USING (true) WITH CHECK (true)`,
    );
    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ${SCHEMA}.${q(EVIL_TABLE)} TO authenticated`);
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
      await admin.end();
    }
  });

  async function canaryAlive(): Promise<boolean> {
    const r = await admin.query(
      `SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'canary'`,
      [SCHEMA],
    );
    return (r.rowCount ?? 0) === 1;
  }

  it("introspects hostile identifiers without executing them", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      // the evil table is present with its literal name
      expect(snapshot.tables.some((t) => t.name === EVIL_TABLE)).toBe(true);
      expect(snapshot.columns.some((c) => c.name === EVIL_COL)).toBe(true);
      expect(await canaryAlive()).toBe(true);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("audits hostile identifiers and still flags the permissive policy", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const findings = auditRls(snapshot);
      expect(findings.some((f) => f.location.table === EVIL_TABLE && f.ruleId === "rls.permissive-true")).toBe(true);
      expect(await canaryAlive()).toBe(true);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("fuzzes hostile identifiers without dropping the canary", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const result = await fuzzRls(conn, snapshot, { roles: ["authenticated"] });
      // it should have probed the evil table (not crashed/skipped on the name)
      expect(result.history.some((h) => h.table.endsWith(EVIL_TABLE))).toBe(true);
      // the permissive USING(true) means a real leak finding should appear
      expect(result.findings.some((f) => f.location.table === EVIL_TABLE)).toBe(true);
      // and crucially, nothing got injected
      expect(await canaryAlive()).toBe(true);
    } finally {
      await conn.end();
    }
  }, 60_000);
});
