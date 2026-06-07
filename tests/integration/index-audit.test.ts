import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, freshSchema, rawClient, testConnection } from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { auditIndexes } from "../../src/checks/indexes/audit.js";

const SCHEMA = "jimmy_idx_it";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

maybe("index coverage (integration)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await freshSchema(admin, SCHEMA);
    // big table, tenant_id unindexed -> seq scan; org_id indexed -> index scan
    await admin.query(`CREATE TABLE ${SCHEMA}.big (id serial primary key, tenant_id uuid, org_id uuid, body text)`);
    await admin.query(`INSERT INTO ${SCHEMA}.big (tenant_id, org_id, body) SELECT gen_random_uuid(), gen_random_uuid(), 'x' FROM generate_series(1, 5000)`);
    await admin.query(`CREATE INDEX big_org_idx ON ${SCHEMA}.big (org_id)`);
    // small table, tenant_id unindexed but below threshold -> not probed
    await admin.query(`CREATE TABLE ${SCHEMA}.small (id serial primary key, tenant_id uuid)`);
    await admin.query(`INSERT INTO ${SCHEMA}.small (tenant_id) SELECT gen_random_uuid() FROM generate_series(1, 10)`);
    await admin.query(`ANALYZE ${SCHEMA}.big`);
    await admin.query(`ANALYZE ${SCHEMA}.small`);
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
      await admin.end();
    }
  });

  it("flags the unindexed lookup on a big table, clears the indexed one and the small table", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const { findings } = await conn.withClient((c) => auditIndexes(c, snapshot, { minRows: 1000 }));
      const cols = findings.map((f) => f.location.column);
      expect(cols).toContain("tenant_id"); // unindexed, big -> flagged
      expect(cols).not.toContain("org_id"); // indexed -> not flagged
      // small.tenant_id is below the row threshold; ensure no finding mentions the small table
      expect(findings.every((f) => f.location.table === "big")).toBe(true);
    } finally {
      await conn.end();
    }
  }, 60_000);
});
