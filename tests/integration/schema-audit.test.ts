import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, freshSchema, rawClient, testConnection } from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { auditSchema } from "../../src/checks/schema/audit.js";

const SCHEMA = "jimmy_schema_it";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

maybe("schema audit (integration)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await freshSchema(admin, SCHEMA);

    // table with no primary key
    await admin.query(`CREATE TABLE ${SCHEMA}.no_pk (name text)`);

    // _id column with no FK and no index, plus nullable tenant_id
    await admin.query(`
      CREATE TABLE ${SCHEMA}.orders (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid,
        tenant_id uuid
      )
    `);

    // clean reference table + proper FK
    await admin.query(`CREATE TABLE ${SCHEMA}.users (id uuid PRIMARY KEY DEFAULT gen_random_uuid())`);
    await admin.query(`
      CREATE TABLE ${SCHEMA}.clean_child (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES ${SCHEMA}.users(id)
      )
    `);
    await admin.query(`CREATE INDEX clean_child_user_id_idx ON ${SCHEMA}.clean_child (user_id)`);
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
      await admin.end();
    }
  });

  it("flags no-pk, missing-fk, fk-no-index, weak-not-null and clears the clean table", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const findings = auditSchema(snapshot);
      const rule = (t: string, r: string) =>
        findings.some((f) => f.location.table === t && f.ruleId === r);

      expect(rule("no_pk", "schema.no-primary-key")).toBe(true);
      expect(rule("orders", "schema.missing-fk")).toBe(true);
      expect(rule("orders", "schema.fk-no-index")).toBe(true);
      expect(rule("orders", "schema.weak-not-null")).toBe(true);

      // clean_child has a real FK and an index on it, so neither fk rule should fire
      expect(rule("clean_child", "schema.missing-fk")).toBe(false);
      expect(rule("clean_child", "schema.fk-no-index")).toBe(false);
    } finally {
      await conn.end();
    }
  }, 60_000);
});
