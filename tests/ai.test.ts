import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveApiKey } from "../src/ai/client.js";
import { buildRemediationPrompt } from "../src/ai/remediate.js";
import { findingId, type Finding } from "../src/report/findings.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  delete process.env.ANTHROPIC_API_KEY;
});

function f(severity: Finding["severity"], rule: string, table?: string): Finding {
  return {
    id: findingId("rls-audit", rule, table ?? rule),
    category: "rls-audit",
    ruleId: rule,
    severity,
    title: `${rule} title`,
    description: "d",
    location: table ? { schema: "public", table } : {},
  };
}

describe("resolveApiKey", () => {
  it("prefers process.env", () => {
    process.env.ANTHROPIC_API_KEY = "env-key";
    expect(resolveApiKey()).toBe("env-key");
  });

  it("reads .env.local when env is unset", () => {
    const dir = mkdtempSync(join(tmpdir(), "jimmy-ai-"));
    dirs.push(dir);
    writeFileSync(join(dir, ".env.local"), 'ANTHROPIC_API_KEY="file-key"\n');
    expect(resolveApiKey(dir)).toBe("file-key");
  });

  it("returns undefined when no key anywhere", () => {
    const dir = mkdtempSync(join(tmpdir(), "jimmy-ai-"));
    dirs.push(dir);
    expect(resolveApiKey(dir)).toBeUndefined();
  });
});

describe("buildRemediationPrompt", () => {
  it("includes the target and the top findings, sorted by severity, capped", () => {
    const findings = [
      f("low", "rls.not-forced", "a"),
      f("critical", "rls.permissive-true", "b"),
      f("high", "rls.disabled", "c"),
    ];
    const p = buildRemediationPrompt(findings, "mydb");
    expect(p).toContain("mydb");
    // critical should appear before high before low in the listing
    expect(p.indexOf("rls.permissive-true")).toBeLessThan(p.indexOf("rls.disabled"));
    expect(p.indexOf("rls.disabled")).toBeLessThan(p.indexOf("rls.not-forced"));
  });

  it("excludes info findings", () => {
    const p = buildRemediationPrompt([f("info", "rls.fuzz.skipped", "x")], "db");
    expect(p).not.toContain("rls.fuzz.skipped");
  });
});
