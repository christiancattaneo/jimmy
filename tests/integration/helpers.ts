/**
 * Integration test helpers. These tests need a real Postgres.
 *
 * Point JIMMY_TEST_DB at a throwaway database:
 *   JIMMY_TEST_DB=postgres://localhost:5432/jimmy_test npm run test:integration
 *
 * If JIMMY_TEST_DB is unset we fall back to a local default so the suite is
 * one command on a dev machine. The database name must look like a test
 * database (jimmy's safety guard enforces this for mutating probes).
 */

import pg from "pg";
import { connect, type JimmyConnection } from "../../src/db/connect.js";
import { SafetyGuard, DEFAULT_SAFETY_CONFIG } from "../../src/safety/index.js";

export const TEST_DB_URL =
  process.env.JIMMY_TEST_DB ?? "postgres://localhost:5432/jimmy_test";

/** A guard that allows mutations against a test-shaped database. */
export function testGuard(): SafetyGuard {
  return new SafetyGuard({
    ...DEFAULT_SAFETY_CONFIG,
    mode: "test-schema",
    statementTimeoutMs: 15_000,
  });
}

/** Open a jimmy connection for the test database. */
export async function testConnection(): Promise<JimmyConnection> {
  return connect({
    connectionString: TEST_DB_URL,
    guard: testGuard(),
    applicationName: "jimmy-integration-test",
  });
}

/** A raw client for fixture setup/teardown (no jimmy safety wrapping). */
export async function rawClient(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: TEST_DB_URL });
  await client.connect();
  return client;
}

/**
 * Probe the database once. Returns null if unreachable so tests can skip
 * cleanly rather than failing the whole suite on a machine with no Postgres.
 */
export async function databaseReachable(): Promise<boolean> {
  try {
    const c = new pg.Client({ connectionString: TEST_DB_URL, connectionTimeoutMillis: 2000 });
    await c.connect();
    await c.query("SELECT 1");
    await c.end();
    return true;
  } catch {
    return false;
  }
}

/** Ensure the supabase-like roles exist (idempotent). */
export async function ensureSupabaseRoles(client: pg.Client): Promise<void> {
  await client.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon NOLOGIN; END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
    END $$;
  `);
}

/** Drop and recreate a schema for an isolated fixture. */
export async function freshSchema(client: pg.Client, schema: string): Promise<void> {
  await client.query(`DROP SCHEMA IF EXISTS ${quote(schema)} CASCADE`);
  await client.query(`CREATE SCHEMA ${quote(schema)}`);
  await client.query(`GRANT USAGE ON SCHEMA ${quote(schema)} TO anon, authenticated`);
}

export function quote(identifier: string): string {
  return `"${identifier.replace(/"/g, '""')}"`;
}
