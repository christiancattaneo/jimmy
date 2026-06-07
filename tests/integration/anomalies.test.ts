import { describe, expect, it } from "vitest";
import { databaseReachable, testConnection } from "./helpers.js";
import { runAnomalyProbes, type ProbeResult } from "../../src/checks/anomalies/probes.js";

const reachable = await databaseReachable();
const maybe = reachable ? describe : describe.skip;

function find(results: ProbeResult[], anomaly: string, level: string): ProbeResult {
  const r = results.find((x) => x.anomaly === anomaly && x.level === level);
  if (!r) throw new Error(`no probe result for ${anomaly} @ ${level}`);
  return r;
}

maybe("anomaly probes (integration)", () => {
  it("reproduces the classical Postgres isolation results", async () => {
    const conn = await testConnection();
    try {
      const { results } = await runAnomalyProbes(conn);

      // SERIALIZABLE must prevent every anomaly we probe.
      for (const anomaly of ["lost-update", "read-skew", "write-skew", "g2-item"] as const) {
        expect(find(results, anomaly, "SERIALIZABLE").observable).toBe(false);
      }

      // Write skew and g2 are observable at REPEATABLE READ on Postgres (snapshot isolation).
      expect(find(results, "write-skew", "REPEATABLE READ").observable).toBe(true);
      expect(find(results, "g2-item", "REPEATABLE READ").observable).toBe(true);

      // Lost update and read skew are prevented by Postgres at REPEATABLE READ
      // (first-updater-wins aborts the loser; snapshot keeps reads consistent).
      expect(find(results, "lost-update", "REPEATABLE READ").observable).toBe(false);
      expect(find(results, "read-skew", "REPEATABLE READ").observable).toBe(false);

      // Phantom: visible at READ COMMITTED, prevented by snapshot isolation at RR+.
      expect(find(results, "phantom", "READ COMMITTED").observable).toBe(true);
      expect(find(results, "phantom", "REPEATABLE READ").observable).toBe(false);
      expect(find(results, "phantom", "SERIALIZABLE").observable).toBe(false);

      // Control: SELECT FOR UPDATE must prevent lost update at EVERY level,
      // including READ COMMITTED. If this ever trips, the engine is broken.
      for (const level of ["READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE"] as const) {
        expect(find(results, "lost-update-for-update", level).observable).toBe(false);
      }
    } finally {
      await conn.end();
    }
  }, 120_000);

  it("cleans up its test schema (no jimmy_anomaly schemas left)", async () => {
    const conn = await testConnection();
    try {
      const leftover = await conn.withClient((c) =>
        c.query(`SELECT nspname FROM pg_namespace WHERE nspname LIKE 'jimmy_anomaly%'`),
      );
      expect(leftover.rowCount ?? 0).toBe(0);
    } finally {
      await conn.end();
    }
  }, 30_000);
});
