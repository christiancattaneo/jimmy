import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, applyDisabledRules } from "../src/config.js";

function tempDirWith(filename: string, contents: string): string {
  const dir = mkdtempSync(join(tmpdir(), "jimmy-cfg-"));
  writeFileSync(join(dir, filename), contents);
  return dir;
}

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("loadConfig", () => {
  it("returns empty config when no file exists", () => {
    const dir = mkdtempSync(join(tmpdir(), "jimmy-cfg-"));
    dirs.push(dir);
    expect(loadConfig(undefined, dir)).toEqual({});
  });

  it("auto-discovers jimmy.config.json", () => {
    const dir = tempDirWith("jimmy.config.json", JSON.stringify({ failOn: "critical", tenantColumns: ["org_id"] }));
    dirs.push(dir);
    const cfg = loadConfig(undefined, dir);
    expect(cfg.failOn).toBe("critical");
    expect(cfg.tenantColumns).toEqual(["org_id"]);
  });

  it("auto-discovers .jimmyrc.json", () => {
    const dir = tempDirWith(".jimmyrc.json", JSON.stringify({ disabledRules: ["rls.not-forced"] }));
    dirs.push(dir);
    expect(loadConfig(undefined, dir).disabledRules).toEqual(["rls.not-forced"]);
  });

  it("throws on an explicit path that does not exist", () => {
    expect(() => loadConfig("/nope/jimmy.config.json")).toThrow(/not found/i);
  });

  it("throws on malformed JSON", () => {
    const dir = tempDirWith("jimmy.config.json", "{ not json");
    dirs.push(dir);
    expect(() => loadConfig(undefined, dir)).toThrow(/parse/i);
  });

  it("rejects unknown keys (strict schema, catches typos)", () => {
    const dir = tempDirWith("jimmy.config.json", JSON.stringify({ failOnn: "high" }));
    dirs.push(dir);
    expect(() => loadConfig(undefined, dir)).toThrow(/invalid config/i);
  });

  it("rejects wrong types", () => {
    const dir = tempDirWith("jimmy.config.json", JSON.stringify({ tenantColumns: "org_id" }));
    dirs.push(dir);
    expect(() => loadConfig(undefined, dir)).toThrow(/invalid config/i);
  });
});

describe("applyDisabledRules", () => {
  const findings = [
    { ruleId: "rls.disabled" },
    { ruleId: "rls.not-forced" },
    { ruleId: "schema.missing-fk" },
  ];

  it("drops disabled rule ids", () => {
    const r = applyDisabledRules(findings, ["rls.not-forced"]);
    expect(r.map((f) => f.ruleId)).toEqual(["rls.disabled", "schema.missing-fk"]);
  });

  it("is a no-op for empty or undefined disabled list", () => {
    expect(applyDisabledRules(findings, [])).toHaveLength(3);
    expect(applyDisabledRules(findings, undefined)).toHaveLength(3);
  });
});
