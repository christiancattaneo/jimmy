import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * End-to-end smoke test of the built CLI binary: exercises commander wiring,
 * exit codes, and the migration linter against the real entry point (which the
 * module-level unit tests do not cover). Skips cleanly if dist is not built.
 */

const CLI = join(process.cwd(), "dist", "cli", "index.js");
const built = existsSync(CLI);
const maybe = built ? describe : describe.skip;

function run(args: string[], cwd: string): { code: number; stdout: string } {
  try {
    const stdout = execFileSync("node", [CLI, ...args], { cwd, encoding: "utf-8" });
    return { code: 0, stdout };
  } catch (e) {
    const err = e as { status?: number; stdout?: string };
    return { code: err.status ?? 1, stdout: err.stdout ?? "" };
  }
}

maybe("cli smoke", () => {
  it("--version prints the version", () => {
    const r = run(["--version"], process.cwd());
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("explain prints a known rule", () => {
    const r = run(["explain", "rls.permissive-true"], process.cwd());
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("rls.permissive-true");
    expect(r.stdout.toLowerCase()).toContain("fix");
  });

  it("explain exits nonzero for an unknown rule", () => {
    expect(run(["explain", "totally.made.up"], process.cwd()).code).not.toBe(0);
  });

  it("migrations lint exits 2 on a dangerous migration and 0 on a safe one", () => {
    const dir = mkdtempSync(join(tmpdir(), "jimmy-smoke-"));
    writeFileSync(join(dir, "bad.sql"), "DROP TABLE users;");
    const bad = run(["migrations", "lint", "--file", join(dir, "bad.sql"), "--quiet", "-o", join(dir, "r")], dir);
    expect(bad.code).toBe(2);
    expect(bad.stdout).toContain("jimmy:");

    writeFileSync(join(dir, "ok.sql"), "SET lock_timeout='5s';\nALTER TABLE t ADD COLUMN x int DEFAULT 0;");
    const ok = run(["migrations", "lint", "--file", join(dir, "ok.sql"), "--fail-on", "high", "--quiet", "-o", join(dir, "r2")], dir);
    expect(ok.code).toBe(0);
  });

  it("production-named db is blocked with exit 3", () => {
    const r = run(["schema", "--db", "postgres://u:p@host/myapp_production"], process.cwd());
    expect(r.code).toBe(3);
  });
});
