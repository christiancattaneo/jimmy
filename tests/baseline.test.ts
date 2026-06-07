import { describe, expect, it } from "vitest";
import { buildBaseline, applyBaseline } from "../src/report/baseline.js";
import { parseFailOn, anyFails, findingId, type Finding } from "../src/report/findings.js";

function f(severity: Finding["severity"], category: Finding["category"], rule: string, scope: string): Finding {
  return {
    id: findingId(category, rule, scope),
    category,
    ruleId: rule,
    severity,
    title: `${rule} ${scope}`,
    description: "d",
    location: {},
  };
}

describe("buildBaseline", () => {
  it("dedupes and sorts ids", () => {
    const a = f("high", "schema", "r", "x");
    const b = f("high", "schema", "r", "x"); // same id
    const c = f("low", "schema", "r2", "y");
    const base = buildBaseline([a, b, c]);
    expect(base.acceptedIds).toHaveLength(2);
    expect(base.acceptedIds).toEqual([...base.acceptedIds].sort());
  });
});

describe("applyBaseline", () => {
  it("separates new findings from baselined ones", () => {
    const existing = f("high", "schema", "old", "x");
    const base = buildBaseline([existing]);
    const fresh = f("critical", "rls-audit", "new", "y");
    const applied = applyBaseline([existing, fresh], base);
    expect(applied.baselined.map((x) => x.ruleId)).toEqual(["old"]);
    expect(applied.newFindings.map((x) => x.ruleId)).toEqual(["new"]);
  });

  it("reports resolved ids when a baselined finding disappears", () => {
    const a = f("high", "schema", "a", "x");
    const b = f("high", "schema", "b", "y");
    const base = buildBaseline([a, b]);
    const applied = applyBaseline([a], base); // b is gone
    expect(applied.resolvedIds).toEqual([b.id]);
  });

  it("a finding keeps its id across line moves (scope-stable)", () => {
    // same category/rule/scope -> same id regardless of where it appears
    expect(findingId("migrations", "migration.drop-table", "f.sql:migration.drop-table:0"))
      .toBe(findingId("migrations", "migration.drop-table", "f.sql:migration.drop-table:0"));
  });
});

describe("parseFailOn", () => {
  it("parses a bare severity", () => {
    expect(parseFailOn("high")).toEqual({ default: "high", byCategory: {} });
  });

  it("parses per-category with default", () => {
    const spec = parseFailOn("default=high,schema=low,migrations=critical");
    expect(spec.default).toBe("high");
    expect(spec.byCategory.schema).toBe("low");
    expect(spec.byCategory.migrations).toBe("critical");
  });

  it("expands the rls alias to both rls categories", () => {
    const spec = parseFailOn("rls=medium");
    expect(spec.byCategory["rls-audit"]).toBe("medium");
    expect(spec.byCategory["rls-fuzz"]).toBe("medium");
  });

  it("throws on invalid severity", () => {
    expect(() => parseFailOn("bogus")).toThrow(/severity/i);
    expect(() => parseFailOn("schema=nope")).toThrow(/severity/i);
  });

  it("throws on unknown category", () => {
    expect(() => parseFailOn("notacat=high")).toThrow(/category/i);
  });
});

describe("anyFails", () => {
  const findings = [
    f("medium", "schema", "a", "x"),
    f("high", "rls-audit", "b", "y"),
  ];

  it("uses the default threshold for unlisted categories", () => {
    expect(anyFails(findings, parseFailOn("high"))).toBe(true);
    expect(anyFails(findings, parseFailOn("critical"))).toBe(false);
  });

  it("applies per-category overrides", () => {
    // schema lowered to medium -> the medium schema finding now trips
    expect(anyFails([f("medium", "schema", "a", "x")], parseFailOn("default=critical,schema=medium"))).toBe(true);
    // rls raised to critical -> the high rls finding no longer trips
    expect(anyFails([f("high", "rls-audit", "b", "y")], parseFailOn("default=critical,rls=critical"))).toBe(false);
  });

  it("returns false on empty findings", () => {
    expect(anyFails([], parseFailOn("info"))).toBe(false);
  });
});
