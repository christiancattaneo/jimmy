import { describe, expect, it } from "vitest";
import { ALL_ISOLATION_LEVELS } from "../src/checks/anomalies/probes.js";

describe("ALL_ISOLATION_LEVELS", () => {
  it("covers postgres' three published isolation levels", () => {
    expect(ALL_ISOLATION_LEVELS).toEqual(["READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE"]);
  });
  it("does not include READ UNCOMMITTED (postgres treats it as READ COMMITTED)", () => {
    expect(ALL_ISOLATION_LEVELS).not.toContain("READ UNCOMMITTED");
  });
});
