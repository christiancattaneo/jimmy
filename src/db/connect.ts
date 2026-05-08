/**
 * Postgres connection. Thin wrapper around node-postgres that enforces the
 * safety guard's session settings on every connection check-out.
 */

import pg from "pg";
import { SafetyGuard, parseConnectionString, type ConnectionShape } from "../safety/index.js";

const { Pool } = pg;
type PgPool = pg.Pool;
type PgPoolClient = pg.PoolClient;

export interface ConnectOptions {
  connectionString: string;
  guard: SafetyGuard;
  /** Application name shown in pg_stat_activity. */
  applicationName?: string;
  /** Pool size. Keep small. */
  max?: number;
}

export interface JimmyConnection {
  pool: PgPool;
  shape: ConnectionShape;
  guard: SafetyGuard;
  /** Acquire a client and apply the safety session settings. */
  withClient<T>(fn: (client: PgPoolClient) => Promise<T>): Promise<T>;
  /** Acquire a client, BEGIN; ...; ROLLBACK; */
  withRollback<T>(fn: (client: PgPoolClient) => Promise<T>): Promise<T>;
  end(): Promise<void>;
}

export async function connect(opts: ConnectOptions): Promise<JimmyConnection> {
  const { guard } = opts;
  const parsed = parseConnectionString(opts.connectionString);
  guard.assertConnection(parsed);

  const pool = new Pool({
    connectionString: opts.connectionString,
    application_name: opts.applicationName ?? "jimmy",
    max: opts.max ?? 4,
    statement_timeout: guard.config.statementTimeoutMs,
    idle_in_transaction_session_timeout: guard.config.statementTimeoutMs,
  });

  pool.on("error", (err) => {
    process.stderr.write(`[jimmy] pool error: ${err.message}\n`);
  });

  const shape: ConnectionShape = {
    host: parsed.host,
    port: parsed.port,
    database: parsed.database,
    user: parsed.user,
  };

  const apply = async (client: PgPoolClient) => {
    await client.query(guard.sessionInitSql());
  };

  return {
    pool,
    shape,
    guard,
    async withClient<T>(fn: (client: PgPoolClient) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await apply(client);
        return await fn(client);
      } finally {
        client.release();
      }
    },
    async withRollback<T>(fn: (client: PgPoolClient) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await apply(client);
        await client.query("BEGIN");
        try {
          const result = await fn(client);
          await client.query("ROLLBACK");
          return result;
        } catch (e) {
          try {
            await client.query("ROLLBACK");
          } catch {
            /* connection already broken */
          }
          throw e;
        }
      } finally {
        client.release();
      }
    },
    async end() {
      await pool.end();
    },
  };
}
