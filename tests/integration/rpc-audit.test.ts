import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, ensureSupabaseRoles, freshSchema, rawClient, testConnection } from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { auditRpc } from "../../src/checks/rls/rpc.js";

const SCHEMA = "jimmy_rpc_it";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

maybe("rpc audit (integration)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await ensureSupabaseRoles(admin);
    // service_role for the locked-down case
    await admin.query(`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF; END $$;`);
    await freshSchema(admin, SCHEMA);

    // leaky: SECURITY DEFINER, default acl (PUBLIC), no search_path
    await admin.query(`CREATE FUNCTION ${SCHEMA}.leaky() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`);

    // locked down: definer, pinned path, service_role only
    await admin.query(`CREATE FUNCTION ${SCHEMA}.locked() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path='' AS 'SELECT 1'`);
    await admin.query(`REVOKE EXECUTE ON FUNCTION ${SCHEMA}.locked() FROM PUBLIC`);
    await admin.query(`GRANT EXECUTE ON FUNCTION ${SCHEMA}.locked() TO service_role`);

    // invoker: not SECURITY DEFINER, should never be flagged even if public
    await admin.query(`CREATE FUNCTION ${SCHEMA}.invoker() RETURNS int LANGUAGE sql AS 'SELECT 1'`);
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
      await admin.end();
    }
  });

  it("flags the leaky definer, clears the locked one, ignores the invoker", async () => {
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const findings = auditRpc(snapshot);

      const byFn = (name: string) => findings.filter((f) => f.location.table === name);
      expect(byFn("leaky").some((f) => f.ruleId === "rpc.definer-public")).toBe(true);
      expect(byFn("leaky").some((f) => f.ruleId === "rpc.definer-search-path")).toBe(true);
      expect(byFn("locked")).toHaveLength(0);
      expect(byFn("invoker")).toHaveLength(0);
    } finally {
      await conn.end();
    }
  }, 60_000);
});
