import { describe, expect, it } from "vitest";
import { buildReport, reportToMarkdown, reportToJson } from "../src/report/generate.js";
import { findingId, isAtOrAbove, type Finding } from "../src/report/findings.js";

function f(severity: Finding["severity"], category: Finding["category"], rule: string, scope: string): Finding {
  return {
    id: findingId(category, rule, scope),
    category,
    ruleId: rule,
    severity,
    title: `${rule} on ${scope}`,
    description: "desc",
    location: {},
  };
}

describe("isAtOrAbove", () => {
  it("compares severities", () => {
    expect(isAtOrAbove("critical", "high")).toBe(true);
    expect(isAtOrAbove("high", "high")).toBe(true);
    expect(isAtOrAbove("medium", "high")).toBe(false);
    expect(isAtOrAbove("info", "low")).toBe(false);
  });
});

describe("findingId", () => {
  it("is deterministic", () => {
    expect(findingId("rls-audit", "rls.disabled", "public.t")).toBe(
      findingId("rls-audit", "rls.disabled", "public.t"),
    );
  });
  it("differs across inputs", () => {
    expect(findingId("rls-audit", "a", "x")).not.toBe(findingId("rls-audit", "a", "y"));
    expect(findingId("rls-audit", "a", "x")).not.toBe(findingId("rls-audit", "b", "x"));
  });
});

describe("buildReport", () => {
  it("sorts findings by severity then category then ruleId", () => {
    const findings: Finding[] = [
      f("low", "schema", "schema.no-pk", "public.a"),
      f("critical", "rls-audit", "rls.disabled", "public.t"),
      f("high", "rls-audit", "rls.bypass-role", "myrole"),
      f("high", "schema", "schema.missing-fk", "public.b"),
    ];
    const r = buildReport(findings, { title: "t", target: "x" });
    expect(r.findings[0]!.severity).toBe("critical");
    expect(r.findings.at(-1)!.severity).toBe("low");
  });

  it("counts severities and categories", () => {
    const findings: Finding[] = [
      f("low", "schema", "a", "x"),
      f("high", "rls-audit", "b", "y"),
      f("high", "rls-audit", "c", "z"),
    ];
    const r = buildReport(findings, { title: "t", target: "x" });
    expect(r.stats.bySeverity.high).toBe(2);
    expect(r.stats.bySeverity.low).toBe(1);
    expect(r.stats.byCategory["rls-audit"]).toBe(2);
  });

  it("two runs produce stable output (deterministic)", () => {
    const findings: Finding[] = [
      f("high", "rls-audit", "b", "y"),
      f("high", "rls-audit", "a", "x"),
      f("low", "schema", "z", "w"),
    ];
    const a = reportToJson(buildReport(findings, { title: "t", target: "d" }));
    const b = reportToJson(buildReport(findings, { title: "t", target: "d" }));
    // generatedAt differs; strip it before comparison
    const stripTime = (s: string) => s.replace(/"generatedAt"\s*:\s*"[^"]*"/g, '"generatedAt":""');
    expect(stripTime(a)).toBe(stripTime(b));
  });

  it("renders markdown without throwing on every severity", () => {
    const findings: Finding[] = [
      f("critical", "rls-audit", "a", "x"),
      f("high", "rls-audit", "b", "y"),
      f("medium", "rls-audit", "c", "z"),
      f("low", "schema", "d", "w"),
      f("info", "nplusone", "e", "v"),
    ];
    const md = reportToMarkdown(buildReport(findings, { title: "t", target: "x" }));
    expect(md).toContain("critical");
    expect(md).toContain("info");
    expect(md).toContain("Findings");
  });

  it("markdown gracefully handles zero findings", () => {
    const md = reportToMarkdown(buildReport([], { title: "t", target: "x" }));
    expect(md).toContain("No findings");
  });
});
