import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, freshSchema, rawClient, testConnection } from "./helpers.js";
import { introspect } from "../../src/db/introspect.js";
import { auditRealtime } from "../../src/checks/realtime/audit.js";
import { auditCron } from "../../src/checks/cron/audit.js";

const SCHEMA = "jimmy_rt_it";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

maybe("realtime + cron audit (integration)", () => {
  let admin: pg.Client;
  let canPublish = true;

  beforeAll(async () => {
    admin = await rawClient();
    await freshSchema(admin, SCHEMA);
    await admin.query(`CREATE TABLE ${SCHEMA}.broadcast_norls (id int primary key, body text)`);
    await admin.query(`CREATE TABLE ${SCHEMA}.broadcast_safe (id int primary key, body text)`);
    await admin.query(`ALTER TABLE ${SCHEMA}.broadcast_safe ENABLE ROW LEVEL SECURITY`);
    await admin.query(`CREATE POLICY p ON ${SCHEMA}.broadcast_safe FOR SELECT USING (true)`);
    try {
      await admin.query(`DROP PUBLICATION IF EXISTS supabase_realtime`);
      await admin.query(`CREATE PUBLICATION supabase_realtime FOR TABLE ${SCHEMA}.broadcast_norls, ${SCHEMA}.broadcast_safe`);
    } catch {
      canPublish = false; // requires create privilege; skip assertions if not granted
    }
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP PUBLICATION IF EXISTS supabase_realtime`).catch(() => undefined);
      await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
      await admin.end();
    }
  });

  it("flags a broadcast table with RLS disabled, clears the protected one", async () => {
    if (!canPublish) return;
    const conn = await testConnection();
    try {
      const snapshot = await conn.withClient((c) => introspect(c, { includeSchemas: [SCHEMA] }));
      const { findings, realtimePresent } = await conn.withClient((c) => auditRealtime(c, snapshot));
      expect(realtimePresent).toBe(true);
      expect(findings.some((f) => f.location.table === "broadcast_norls" && f.ruleId === "realtime.broadcast-no-rls")).toBe(true);
      expect(findings.some((f) => f.location.table === "broadcast_safe")).toBe(false);
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("cron audit is a clean no-op when pg_cron is not installed", async () => {
    const conn = await testConnection();
    try {
      const { findings, cronPresent } = await conn.withClient((c) => auditCron(c));
      // On a vanilla local Postgres pg_cron is absent; assert the no-op contract.
      if (!cronPresent) {
        expect(findings).toHaveLength(0);
      }
    } finally {
      await conn.end();
    }
  }, 30_000);
});
