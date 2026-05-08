import { describe, expect, it } from "vitest";
import { templatize, detectNplusOne } from "../src/checks/nplusone/detect.js";

describe("templatize", () => {
  it("collapses string literals to ?", () => {
    expect(templatize("SELECT * FROM t WHERE name = 'alice'")).toContain("?");
    expect(templatize("SELECT * FROM t WHERE name = 'alice'")).not.toContain("alice");
  });

  it("handles escaped single quotes", () => {
    expect(templatize("SELECT * FROM t WHERE x = 'it''s fine'")).not.toContain("fine");
  });

  it("collapses numeric literals", () => {
    expect(templatize("SELECT * FROM t WHERE id = 42")).toContain("?");
    expect(templatize("SELECT * FROM t WHERE x = 3.14")).toContain("?");
  });

  it("collapses IN-lists of variable size to a single token", () => {
    const a = templatize("SELECT * FROM t WHERE id IN (1, 2, 3, 4, 5)");
    const b = templatize("SELECT * FROM t WHERE id IN (10, 20)");
    expect(a).toBe(b);
  });

  it("normalizes positional placeholders", () => {
    expect(templatize("SELECT * FROM t WHERE id = $1")).toBe(templatize("SELECT * FROM t WHERE id = $5"));
  });

  it("normalizes whitespace and case", () => {
    expect(templatize("SELECT  *\n  FROM  T  WHERE id = 1")).toBe("select * from t where id = ?");
  });

  it("two structurally identical queries with different literals share a template", () => {
    const a = templatize("SELECT * FROM users WHERE id = 1 AND name = 'alice'");
    const b = templatize("SELECT * FROM users WHERE id = 999 AND name = 'bob'");
    expect(a).toBe(b);
  });

  it("structurally different queries do NOT share a template", () => {
    const a = templatize("SELECT * FROM users WHERE id = 1");
    const b = templatize("SELECT * FROM accounts WHERE id = 1");
    expect(a).not.toBe(b);
  });

  it("strips line and block comments", () => {
    expect(templatize("/* comment */ SELECT 1 -- trailing")).not.toContain("comment");
    expect(templatize("/* comment */ SELECT 1 -- trailing")).not.toContain("trailing");
  });
});

describe("detectNplusOne", () => {
  it("flags templates above the threshold", () => {
    const f = detectNplusOne(
      [
        { query: "SELECT 1 FROM t WHERE id = $1", template: "select 1 from t where id = ?", calls: 200, totalMs: 100, meanMs: 0.5 },
      ],
      { threshold: 50 },
    );
    expect(f).toHaveLength(1);
  });

  it("does not flag templates below the threshold", () => {
    const f = detectNplusOne(
      [{ query: "SELECT 1", template: "select 1", calls: 5, totalMs: 1, meanMs: 0.2 }],
      { threshold: 50 },
    );
    expect(f).toEqual([]);
  });

  it("escalates severity for very high call counts", () => {
    const f = detectNplusOne(
      [{ query: "SELECT 1", template: "select 1", calls: 10000, totalMs: 1000, meanMs: 0.1 }],
      { threshold: 50 },
    );
    expect(f[0]!.severity).toBe("high");
  });

  it("respects minTotalMs", () => {
    const f = detectNplusOne(
      [{ query: "SELECT 1", template: "select 1", calls: 1000, totalMs: 5, meanMs: 0.005 }],
      { threshold: 50, minTotalMs: 100 },
    );
    expect(f).toEqual([]);
  });

  it("does not flag templates that lack timing info but are below threshold", () => {
    const f = detectNplusOne(
      [{ query: "SELECT 1", template: "select 1", calls: 10, totalMs: 0, meanMs: 0 }],
      { threshold: 50 },
    );
    expect(f).toEqual([]);
  });
});
