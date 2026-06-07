import { describe, expect, it } from "vitest";
import { CATALOG, explainRule, listRules } from "../src/report/catalog.js";

describe("rule catalog", () => {
  it("has unique ids", () => {
    const ids = CATALOG.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every entry has a summary, why, and fix", () => {
    for (const r of CATALOG) {
      expect(r.summary.length, r.id).toBeGreaterThan(0);
      expect(r.why.length, r.id).toBeGreaterThan(0);
      expect(r.fix.length, r.id).toBeGreaterThan(0);
    }
  });

  it("explains an exact rule id", () => {
    expect(explainRule("rls.permissive-true")?.severity).toBe("critical");
    expect(explainRule("rpc.definer-public")?.id).toBe("rpc.definer-public");
  });

  it("collapses fuzz rule ids to one explanation", () => {
    expect(explainRule("rls.fuzz.select")?.id).toBe("rls.fuzz.*");
    expect(explainRule("rls.fuzz.insert-foreign")?.id).toBe("rls.fuzz.*");
  });

  it("falls back to a generic migration explanation for uncatalogued migration rules", () => {
    const d = explainRule("migration.some-future-rule");
    expect(d).toBeDefined();
    expect(d!.fix).toMatch(/online|concurrently|two-phase/i);
  });

  it("returns undefined for an unknown rule outside known families", () => {
    expect(explainRule("totally.made.up")).toBeUndefined();
  });

  it("listRules is sorted by id", () => {
    const ids = listRules().map((r) => r.id);
    expect(ids).toEqual([...ids].sort());
  });
});
