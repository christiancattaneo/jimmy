/**
 * Hermitage-style transactional anomaly probes.
 *
 * Each probe runs a fixed concurrent workload at every isolation level the
 * database supports and reports which anomalies are observable. The probes
 * use a dedicated test schema and clean up after themselves.
 *
 * References:
 *   https://github.com/ept/hermitage
 *   https://jepsen.io/consistency
 *
 * The probes are intentionally written without external concurrency
 * primitives. We open two clients, advance each one statement at a time in
 * the canonical interleaving for the anomaly, and then read back the result.
 */

import type pg from "pg";
import { randomUUID } from "node:crypto";
import type { JimmyConnection } from "../../db/connect.js";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

type Client = pg.PoolClient;

export type IsolationLevel =
  | "READ COMMITTED"
  | "REPEATABLE READ"
  | "SERIALIZABLE";

export const ALL_ISOLATION_LEVELS: IsolationLevel[] = [
  "READ COMMITTED",
  "REPEATABLE READ",
  "SERIALIZABLE",
];

export type AnomalyName = "lost-update" | "write-skew" | "read-skew" | "g2-item";

export interface ProbeResult {
  anomaly: AnomalyName;
  level: IsolationLevel;
  observable: boolean;
  detail: string;
}

export interface AnomaliesOptions {
  isolationLevels?: IsolationLevel[];
  testSchema?: string;
  anomalies?: AnomalyName[];
}

const DEFAULT_TEST_SCHEMA = "jimmy_anomaly";

async function withTwoClients<T>(
  conn: JimmyConnection,
  fn: (a: Client, b: Client) => Promise<T>,
): Promise<T> {
  const a = await conn.pool.connect();
  const b = await conn.pool.connect();
  try {
    await a.query(conn.guard.sessionInitSql());
    await b.query(conn.guard.sessionInitSql());
    return await fn(a, b);
  } finally {
    a.release();
    b.release();
  }
}

async function setupSchema(client: Client, schema: string): Promise<void> {
  await client.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
  await client.query(`SET LOCAL search_path TO ${schema}`);
  await client.query(`DROP TABLE IF EXISTS ${schema}.kv CASCADE`);
  await client.query(
    `CREATE TABLE ${schema}.kv (id INT PRIMARY KEY, val INT NOT NULL, tag TEXT NOT NULL)`,
  );
}

async function teardownSchema(client: Client, schema: string): Promise<void> {
  await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
}

async function reseed(client: Client, schema: string, rows: Array<[number, number, string]>) {
  await client.query(`TRUNCATE ${schema}.kv`);
  if (rows.length === 0) return;
  const values = rows.map(([id, val, tag], i) => `($${i * 3 + 1}, $${i * 3 + 2}, $${i * 3 + 3})`);
  const params: (number | string)[] = rows.flatMap(([id, val, tag]) => [id, val, tag]);
  await client.query(`INSERT INTO ${schema}.kv (id, val, tag) VALUES ${values.join(", ")}`, params);
}

async function inTx(client: Client, level: IsolationLevel, fn: () => Promise<void>): Promise<{ aborted: boolean; error?: Error }> {
  await client.query(`BEGIN ISOLATION LEVEL ${level}`);
  try {
    await fn();
    await client.query("COMMIT");
    return { aborted: false };
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* connection might be dead */
    }
    return { aborted: true, error: e as Error };
  }
}

/**
 * P4 (lost update). Two transactions read x, both increment, both write.
 * Both commit. The second write should not silently overwrite the first.
 */
async function probeLostUpdate(
  conn: JimmyConnection,
  schema: string,
  level: IsolationLevel,
): Promise<ProbeResult> {
  return withTwoClients(conn, async (a, b) => {
    await reseed(a, schema, [[1, 10, "x"]]);
    let aResult: { aborted: boolean; error?: Error } = { aborted: false };
    let bResult: { aborted: boolean; error?: Error } = { aborted: false };
    await a.query(`BEGIN ISOLATION LEVEL ${level}`);
    await b.query(`BEGIN ISOLATION LEVEL ${level}`);
    try {
      const ar = await a.query(`SELECT val FROM ${schema}.kv WHERE id = 1`);
      const br = await b.query(`SELECT val FROM ${schema}.kv WHERE id = 1`);
      const aRow = ar.rows[0] as { val: number } | undefined;
      const bRow = br.rows[0] as { val: number } | undefined;
      const aVal = aRow?.val ?? 0;
      const bVal = bRow?.val ?? 0;
      try {
        await a.query(`UPDATE ${schema}.kv SET val = $1 WHERE id = 1`, [aVal + 1]);
        await a.query("COMMIT");
        aResult = { aborted: false };
      } catch (e) {
        await a.query("ROLLBACK").catch(() => undefined);
        aResult = { aborted: true, error: e as Error };
      }
      try {
        await b.query(`UPDATE ${schema}.kv SET val = $1 WHERE id = 1`, [bVal + 1]);
        await b.query("COMMIT");
        bResult = { aborted: false };
      } catch (e) {
        await b.query("ROLLBACK").catch(() => undefined);
        bResult = { aborted: true, error: e as Error };
      }
    } finally {
      await a.query("ROLLBACK").catch(() => undefined);
      await b.query("ROLLBACK").catch(() => undefined);
    }
    const final = await a.query(`SELECT val FROM ${schema}.kv WHERE id = 1`);
    const finalRow = final.rows[0] as { val: number } | undefined;
    const finalVal = finalRow?.val ?? 0;
    const bothCommitted = !aResult.aborted && !bResult.aborted;
    const observable = bothCommitted && finalVal === 11;
    const detail = bothCommitted
      ? `final value ${finalVal}; expected 12 if both increments preserved`
      : `lost-update prevented; one transaction was aborted (${aResult.aborted ? "tx A" : "tx B"})`;
    return { anomaly: "lost-update", level, observable, detail };
  });
}

/**
 * Read skew (G-single). Two rows that should sum to a constant are read
 * across a concurrent update.
 */
async function probeReadSkew(
  conn: JimmyConnection,
  schema: string,
  level: IsolationLevel,
): Promise<ProbeResult> {
  return withTwoClients(conn, async (a, b) => {
    await reseed(a, schema, [
      [1, 50, "balance"],
      [2, 50, "balance"],
    ]);
    let observable = false;
    let detail = "";
    await a.query(`BEGIN ISOLATION LEVEL ${level}`);
    try {
      const r1 = await a.query(`SELECT val FROM ${schema}.kv WHERE id = 1`);
      const aRow1 = r1.rows[0] as { val: number } | undefined;
      const txnB = await inTx(b, level, async () => {
        await b.query(`UPDATE ${schema}.kv SET val = val - 20 WHERE id = 1`);
        await b.query(`UPDATE ${schema}.kv SET val = val + 20 WHERE id = 2`);
      });
      const r2 = await a.query(`SELECT val FROM ${schema}.kv WHERE id = 2`);
      const aRow2 = r2.rows[0] as { val: number } | undefined;
      const v1 = aRow1?.val ?? 0;
      const v2 = aRow2?.val ?? 0;
      observable = !txnB.aborted && v1 + v2 !== 100;
      detail = `tx A saw v1=${v1} v2=${v2}; sum=${v1 + v2} (invariant: 100)`;
    } finally {
      await a.query("COMMIT").catch(() => undefined);
    }
    return { anomaly: "read-skew", level, observable, detail };
  });
}

/**
 * Write skew. Classic example: doctors-on-call. Two transactions read the
 * same predicate, then write disjoint rows that each individually satisfy
 * the constraint while breaking it together.
 */
async function probeWriteSkew(
  conn: JimmyConnection,
  schema: string,
  level: IsolationLevel,
): Promise<ProbeResult> {
  return withTwoClients(conn, async (a, b) => {
    await reseed(a, schema, [
      [1, 1, "on-call"],
      [2, 1, "on-call"],
    ]);
    await a.query(`BEGIN ISOLATION LEVEL ${level}`);
    await b.query(`BEGIN ISOLATION LEVEL ${level}`);
    let aResult: { aborted: boolean; error?: Error } = { aborted: false };
    let bResult: { aborted: boolean; error?: Error } = { aborted: false };
    try {
      const ra = await a.query(`SELECT COUNT(*)::int AS c FROM ${schema}.kv WHERE val = 1 AND tag = 'on-call'`);
      const rb = await b.query(`SELECT COUNT(*)::int AS c FROM ${schema}.kv WHERE val = 1 AND tag = 'on-call'`);
      const cA = ((ra.rows[0] as { c: number } | undefined)?.c) ?? 0;
      const cB = ((rb.rows[0] as { c: number } | undefined)?.c) ?? 0;
      if (cA >= 2) {
        try {
          await a.query(`UPDATE ${schema}.kv SET val = 0 WHERE id = 1`);
          await a.query("COMMIT");
        } catch (e) {
          await a.query("ROLLBACK").catch(() => undefined);
          aResult = { aborted: true, error: e as Error };
        }
      }
      if (cB >= 2) {
        try {
          await b.query(`UPDATE ${schema}.kv SET val = 0 WHERE id = 2`);
          await b.query("COMMIT");
        } catch (e) {
          await b.query("ROLLBACK").catch(() => undefined);
          bResult = { aborted: true, error: e as Error };
        }
      }
    } finally {
      await a.query("ROLLBACK").catch(() => undefined);
      await b.query("ROLLBACK").catch(() => undefined);
    }
    const final = await a.query(`SELECT COUNT(*)::int AS c FROM ${schema}.kv WHERE val = 1 AND tag = 'on-call'`);
    const finalCount = ((final.rows[0] as { c: number } | undefined)?.c) ?? 0;
    const bothCommitted = !aResult.aborted && !bResult.aborted;
    const observable = bothCommitted && finalCount === 0;
    const detail = bothCommitted
      ? `both transactions committed; on-call count is ${finalCount} (invariant: at least 1)`
      : `write-skew prevented; one transaction aborted (${aResult.aborted ? "tx A" : "tx B"})`;
    return { anomaly: "write-skew", level, observable, detail };
  });
}

/**
 * G2-item. Two transactions touch overlapping items, each writes one,
 * neither sees the other's write, and the final state breaks an invariant
 * over both items. Detected as a serialization failure under SERIALIZABLE.
 */
async function probeG2Item(
  conn: JimmyConnection,
  schema: string,
  level: IsolationLevel,
): Promise<ProbeResult> {
  return withTwoClients(conn, async (a, b) => {
    await reseed(a, schema, [
      [1, 0, "x"],
      [2, 0, "x"],
    ]);
    await a.query(`BEGIN ISOLATION LEVEL ${level}`);
    await b.query(`BEGIN ISOLATION LEVEL ${level}`);
    let aResult: { aborted: boolean; error?: Error } = { aborted: false };
    let bResult: { aborted: boolean; error?: Error } = { aborted: false };
    try {
      await a.query(`SELECT val FROM ${schema}.kv WHERE id IN (1, 2)`);
      await b.query(`SELECT val FROM ${schema}.kv WHERE id IN (1, 2)`);
      try {
        await a.query(`UPDATE ${schema}.kv SET val = (SELECT val FROM ${schema}.kv WHERE id = 2) + 1 WHERE id = 1`);
        await a.query("COMMIT");
      } catch (e) {
        await a.query("ROLLBACK").catch(() => undefined);
        aResult = { aborted: true, error: e as Error };
      }
      try {
        await b.query(`UPDATE ${schema}.kv SET val = (SELECT val FROM ${schema}.kv WHERE id = 1) + 1 WHERE id = 2`);
        await b.query("COMMIT");
      } catch (e) {
        await b.query("ROLLBACK").catch(() => undefined);
        bResult = { aborted: true, error: e as Error };
      }
    } finally {
      await a.query("ROLLBACK").catch(() => undefined);
      await b.query("ROLLBACK").catch(() => undefined);
    }
    const final = await a.query(`SELECT id, val FROM ${schema}.kv ORDER BY id`);
    const v1 = ((final.rows[0] as { val: number } | undefined)?.val) ?? 0;
    const v2 = ((final.rows[1] as { val: number } | undefined)?.val) ?? 0;
    const bothCommitted = !aResult.aborted && !bResult.aborted;
    const observable = bothCommitted && v1 === 1 && v2 === 1;
    const detail = bothCommitted
      ? `both committed: id=1 val=${v1}, id=2 val=${v2} (anti-dependency cycle present)`
      : `G2 prevented; one transaction aborted (${aResult.aborted ? "tx A" : "tx B"})`;
    return { anomaly: "g2-item", level, observable, detail };
  });
}

const PROBES: Record<AnomalyName, (c: JimmyConnection, s: string, l: IsolationLevel) => Promise<ProbeResult>> = {
  "lost-update": probeLostUpdate,
  "read-skew": probeReadSkew,
  "write-skew": probeWriteSkew,
  "g2-item": probeG2Item,
};

export interface AnomaliesResult {
  results: ProbeResult[];
  findings: Finding[];
}

export async function runAnomalyProbes(
  conn: JimmyConnection,
  opts: AnomaliesOptions = {},
): Promise<AnomaliesResult> {
  conn.guard.assertMutation(conn.shape);
  const schema = opts.testSchema ?? `${DEFAULT_TEST_SCHEMA}_${randomUUID().replace(/-/g, "").slice(0, 8)}`;
  const levels = opts.isolationLevels ?? ALL_ISOLATION_LEVELS;
  const wanted = opts.anomalies ?? (Object.keys(PROBES) as AnomalyName[]);
  const results: ProbeResult[] = [];

  await conn.withClient(async (client) => {
    await setupSchema(client, schema);
  });

  try {
    for (const anomaly of wanted) {
      const probe = PROBES[anomaly];
      for (const level of levels) {
        const result = await probe(conn, schema, level);
        results.push(result);
      }
    }
  } finally {
    await conn.withClient(async (client) => {
      await teardownSchema(client, schema);
    });
  }

  const findings = anomaliesToFindings(results);
  return { results, findings };
}

function anomaliesToFindings(results: ProbeResult[]): Finding[] {
  const out: Finding[] = [];
  const expectedSafeFloor: Record<AnomalyName, IsolationLevel> = {
    "lost-update": "REPEATABLE READ",
    "read-skew": "REPEATABLE READ",
    "write-skew": "SERIALIZABLE",
    "g2-item": "SERIALIZABLE",
  };
  for (const r of results) {
    if (!r.observable) continue;
    const floor = expectedSafeFloor[r.anomaly];
    const sev: Severity = r.level === floor ? "high" : "medium";
    out.push({
      id: findingId("anomalies", `anomaly.${r.anomaly}`, `${r.level}`),
      category: "anomalies",
      ruleId: `anomaly.${r.anomaly}`,
      severity: sev,
      title: `${r.anomaly} observable at ${r.level}`,
      description: `${describeAnomaly(r.anomaly)} ${r.detail}. Use at least ${floor} on this database, or guard the workload with explicit locks (SELECT ... FOR UPDATE).`,
      location: {},
      evidence: { level: r.level, anomaly: r.anomaly, detail: r.detail },
    });
  }
  return out;
}

function describeAnomaly(name: AnomalyName): string {
  switch (name) {
    case "lost-update":
      return "Two concurrent read-modify-write cycles silently overwrite each other.";
    case "read-skew":
      return "A transaction sees two related rows at different points in time, breaking a between-rows invariant.";
    case "write-skew":
      return "Two transactions read overlapping rows, each writes a disjoint row, and together they violate a predicate that held under the read snapshot.";
    case "g2-item":
      return "An anti-dependency cycle between two transactions produces a non-serializable history.";
  }
}

export const _internal = { setupSchema, teardownSchema, reseed, PROBES };
