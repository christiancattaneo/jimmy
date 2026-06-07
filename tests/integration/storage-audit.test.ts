import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { databaseReachable, ensureSupabaseRoles, rawClient, testConnection } from "./helpers.js";
import { auditStorage } from "../../src/checks/storage/audit.js";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

maybe("storage audit (integration)", () => {
  let admin: pg.Client;

  beforeAll(async () => {
    admin = await rawClient();
    await ensureSupabaseRoles(admin);
    // Build a minimal storage schema resembling Supabase's.
    await admin.query(`CREATE SCHEMA IF NOT EXISTS storage`);
    await admin.query(`DROP TABLE IF EXISTS storage.objects CASCADE`);
    await admin.query(`DROP TABLE IF EXISTS storage.buckets CASCADE`);
    await admin.query(`CREATE TABLE storage.buckets (id text PRIMARY KEY, name text NOT NULL, public boolean DEFAULT false, file_size_limit bigint, allowed_mime_types text[])`);
    await admin.query(`CREATE TABLE storage.objects (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), bucket_id text, name text, owner uuid)`);
    await admin.query(`INSERT INTO storage.buckets (id, name, public, file_size_limit) VALUES ('avatars','avatars',true,5242880),('invoices','invoices',false,NULL)`);
    await admin.query(`ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY`);
    await admin.query(`CREATE POLICY wide ON storage.objects FOR SELECT TO authenticated USING (true)`);
  }, 60_000);

  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS storage CASCADE`);
      await admin.end();
    }
  });

  it("flags public bucket, missing size limit, and a permissive objects policy", async () => {
    const conn = await testConnection();
    try {
      const { findings, storagePresent } = await conn.withClient((c) => auditStorage(c));
      expect(storagePresent).toBe(true);
      const rules = findings.map((f) => f.ruleId);
      expect(rules).toContain("storage.public-bucket");
      expect(rules).toContain("storage.no-size-limit");
      expect(rules).toContain("storage.permissive-policy");
      // the public-bucket finding should point at the avatars bucket
      expect(findings.find((f) => f.ruleId === "storage.public-bucket")?.location.table).toBe("avatars");
    } finally {
      await conn.end();
    }
  }, 60_000);

  it("is a clean no-op when no storage schema exists", async () => {
    // a fresh connection against a db without storage.buckets returns nothing.
    await admin.query(`DROP SCHEMA IF EXISTS storage CASCADE`);
    const conn = await testConnection();
    try {
      const { findings, storagePresent } = await conn.withClient((c) => auditStorage(c));
      expect(storagePresent).toBe(false);
      expect(findings).toHaveLength(0);
    } finally {
      await conn.end();
    }
  }, 60_000);
});
