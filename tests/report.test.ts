import { describe, expect, it } from "vitest";
import { buildReport, reportToMarkdown, reportToJson, reportToSarif } from "../src/report/generate.js";
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

  it("groups findings by category with a table of contents", () => {
    const findings: Finding[] = [
      f("critical", "rls-audit", "a", "x"),
      f("high", "migrations", "b", "y"),
      f("low", "schema", "c", "z"),
    ];
    const md = reportToMarkdown(buildReport(findings, { title: "t", target: "x" }));
    // TOC links with counts
    expect(md).toContain("[Row-level security](#row-level-security) (1)");
    expect(md).toContain("[Migration safety](#migration-safety) (1)");
    expect(md).toContain("[Schema integrity](#schema-integrity) (1)");
    // category section headers
    expect(md).toContain("## Row-level security");
    expect(md).toContain("## Migration safety");
  });

  it("markdown gracefully handles zero findings", () => {
    const md = reportToMarkdown(buildReport([], { title: "t", target: "x" }));
    expect(md).toContain("No findings");
  });
});

describe("reportToSarif", () => {
  it("produces valid sarif 2.1.0 structure", () => {
    const findings: Finding[] = [
      { ...f("critical", "migrations", "migration.drop-table", "x"), location: { file: "/db/m.sql", line: 5 } },
      f("high", "rls-audit", "rls.disabled", "public.t"),
    ];
    const sarif = JSON.parse(reportToSarif(buildReport(findings, { title: "t", target: "x" })));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("jimmy");
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it("maps severities to sarif levels", () => {
    const sarif = JSON.parse(
      reportToSarif(
        buildReport(
          [f("critical", "schema", "a", "x"), f("medium", "schema", "b", "y"), f("low", "schema", "c", "z")],
          { title: "t", target: "x" },
        ),
      ),
    );
    const levels = sarif.runs[0].results.map((r: { level: string }) => r.level);
    expect(levels).toContain("error");
    expect(levels).toContain("warning");
    expect(levels).toContain("note");
  });

  it("strips leading slash from file uris and gives db findings a synthetic uri", () => {
    const findings: Finding[] = [
      { ...f("high", "migrations", "r", "x"), location: { file: "/abs/path/m.sql", line: 2 } },
      { ...f("high", "rls-audit", "rls.disabled", "public.users"), location: { schema: "public", table: "users" } },
    ];
    const sarif = JSON.parse(reportToSarif(buildReport(findings, { title: "t", target: "x" })));
    const uris = sarif.runs[0].results.map(
      (r: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }) =>
        r.locations[0].physicalLocation.artifactLocation.uri,
    );
    expect(uris).toContain("abs/path/m.sql");
    expect(uris.some((u: string) => u.startsWith("db/public/users"))).toBe(true);
  });

  it("every result carries a location (github requires it)", () => {
    const sarif = JSON.parse(
      reportToSarif(buildReport([f("info", "anomalies", "a", "x")], { title: "t", target: "x" })),
    );
    for (const r of sarif.runs[0].results) {
      expect(r.locations[0].physicalLocation.region.startLine).toBeGreaterThanOrEqual(1);
    }
  });
});
