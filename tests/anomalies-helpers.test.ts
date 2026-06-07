import { describe, expect, it } from "vitest";
import { ALL_ISOLATION_LEVELS, runAnomalyProbes, recommendIsolationLevel, type ProbeResult } from "../src/checks/anomalies/probes.js";
import { SafetyGuard, DEFAULT_SAFETY_CONFIG } from "../src/safety/index.js";

describe("ALL_ISOLATION_LEVELS", () => {
  it("covers postgres' three published isolation levels", () => {
    expect(ALL_ISOLATION_LEVELS).toEqual(["READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE"]);
  });
  it("does not include READ UNCOMMITTED (postgres treats it as READ COMMITTED)", () => {
    expect(ALL_ISOLATION_LEVELS).not.toContain("READ UNCOMMITTED");
  });
});

describe("runAnomalyProbes test-schema guard", () => {
  // A connection object whose guard allows mutation but never actually
  // connects: the schema-name validation must throw before any query runs.
  const fakeConn = {
    shape: { host: "h", port: 5432, database: "jimmy_test", user: "u" },
    guard: new SafetyGuard({ ...DEFAULT_SAFETY_CONFIG, mode: "test-schema" }),
  } as never;

  it("rejects a hostile testSchema before doing anything", async () => {
    await expect(
      runAnomalyProbes(fakeConn, { testSchema: 'evil"; DROP TABLE x; --' }),
    ).rejects.toThrow(/unsafe test schema/i);
  });

  it("rejects a schema with a space", async () => {
    await expect(runAnomalyProbes(fakeConn, { testSchema: "two words" })).rejects.toThrow(/unsafe/i);
  });

  it("rejects an over-long schema name", async () => {
    await expect(runAnomalyProbes(fakeConn, { testSchema: "a".repeat(64) })).rejects.toThrow(/unsafe/i);
  });
});

describe("recommendIsolationLevel", () => {
  function r(anomaly: string, level: string, observable: boolean): ProbeResult {
    return { anomaly: anomaly as ProbeResult["anomaly"], level: level as ProbeResult["level"], observable, detail: "" };
  }

  it("recommends the lowest level with no observable anomaly (classic postgres)", () => {
    const results: ProbeResult[] = [
      r("write-skew", "READ COMMITTED", true),
      r("write-skew", "REPEATABLE READ", true),
      r("write-skew", "SERIALIZABLE", false),
      r("lost-update", "READ COMMITTED", true),
      r("lost-update", "REPEATABLE READ", false),
      r("lost-update", "SERIALIZABLE", false),
    ];
    expect(recommendIsolationLevel(results)).toBe("SERIALIZABLE");
  });

  it("recommends READ COMMITTED when nothing is observable anywhere", () => {
    const results: ProbeResult[] = [r("lost-update", "READ COMMITTED", false)];
    expect(recommendIsolationLevel(results)).toBe("READ COMMITTED");
  });

  it("ignores the FOR UPDATE control probe", () => {
    const results: ProbeResult[] = [
      r("lost-update-for-update", "READ COMMITTED", true), // would never really happen
      r("lost-update", "READ COMMITTED", false),
    ];
    // the control is ignored, so READ COMMITTED is still recommended
    expect(recommendIsolationLevel(results)).toBe("READ COMMITTED");
  });

  it("returns null if even SERIALIZABLE shows an anomaly", () => {
    const results: ProbeResult[] = [
      r("write-skew", "READ COMMITTED", true),
      r("write-skew", "REPEATABLE READ", true),
      r("write-skew", "SERIALIZABLE", true),
    ];
    expect(recommendIsolationLevel(results)).toBeNull();
  });
});
