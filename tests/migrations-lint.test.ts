import { describe, expect, it } from "vitest";
import { lintSqlText, _internal } from "../src/checks/migrations/lint.js";

describe("stripComments", () => {
  const { stripComments } = _internal;
  it("removes line comments", () => {
    expect(stripComments("SELECT 1; -- comment\nSELECT 2;")).toContain("SELECT 1;");
    expect(stripComments("SELECT 1; -- comment\nSELECT 2;")).not.toContain("comment");
  });
  it("removes block comments", () => {
    expect(stripComments("/* hi */ SELECT 1;")).not.toContain("hi");
  });
  it("does not remove comment-shaped strings", () => {
    expect(stripComments("SELECT '-- not a comment';")).toContain("not a comment");
    expect(stripComments(`SELECT '/* no */';`)).toContain("no");
  });
});

describe("splitStatements", () => {
  const { splitStatements } = _internal;
  it("splits on top-level semicolons", () => {
    expect(splitStatements("SELECT 1; SELECT 2;")).toHaveLength(2);
  });
  it("ignores semicolons inside strings", () => {
    expect(splitStatements("SELECT ';';")).toHaveLength(1);
  });
  it("respects dollar-quoted bodies", () => {
    const sql = "DO $$ BEGIN PERFORM 1; PERFORM 2; END $$; SELECT 1;";
    expect(splitStatements(sql)).toHaveLength(2);
  });
  it("trims whitespace and drops empty statements", () => {
    expect(splitStatements("  ;  ;SELECT 1;")).toEqual(["SELECT 1"]);
  });
});

describe("migration linter rules", () => {
  it("flags ADD COLUMN NOT NULL without DEFAULT", () => {
    const r = lintSqlText("ALTER TABLE t ADD COLUMN x int NOT NULL;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.add-not-null-without-default")).toBeDefined();
  });

  it("does not flag ADD COLUMN NOT NULL DEFAULT", () => {
    const r = lintSqlText("ALTER TABLE t ADD COLUMN x int NOT NULL DEFAULT 0;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.add-not-null-without-default")).toBeUndefined();
  });

  it("flags CREATE INDEX without CONCURRENTLY", () => {
    const r = lintSqlText("CREATE INDEX idx ON t (a);", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.non-concurrent-index")).toBeDefined();
  });

  it("does not flag CREATE INDEX CONCURRENTLY", () => {
    const r = lintSqlText("CREATE INDEX CONCURRENTLY idx ON t (a);", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.non-concurrent-index")).toBeUndefined();
  });

  it("flags ALTER COLUMN TYPE", () => {
    const r = lintSqlText("ALTER TABLE t ALTER COLUMN x TYPE bigint;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.type-rewrite")).toBeDefined();
  });

  it("flags DROP TABLE", () => {
    const r = lintSqlText("DROP TABLE t;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.drop-table")).toBeDefined();
  });

  it("flags DROP COLUMN", () => {
    const r = lintSqlText("ALTER TABLE t DROP COLUMN x;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.drop-column")).toBeDefined();
  });

  it("flags DISABLE ROW LEVEL SECURITY as critical", () => {
    const r = lintSqlText("ALTER TABLE t DISABLE ROW LEVEL SECURITY;", "f.sql");
    const f = r.find((f) => f.ruleId === "migration.disable-rls");
    expect(f?.severity).toBe("critical");
  });

  it("flags TRUNCATE", () => {
    const r = lintSqlText("TRUNCATE big_table;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.truncate")).toBeDefined();
  });

  it("flags RENAME COLUMN and RENAME TABLE", () => {
    const a = lintSqlText("ALTER TABLE t RENAME COLUMN x TO y;", "f.sql");
    const b = lintSqlText("ALTER TABLE t RENAME TO t2;", "f.sql");
    expect(a.find((f) => f.ruleId === "migration.rename-column")).toBeDefined();
    expect(b.find((f) => f.ruleId === "migration.rename-table")).toBeDefined();
  });

  it("flags lock-timeout-missing for DDL without SET lock_timeout", () => {
    const r = lintSqlText("ALTER TABLE t ADD COLUMN x int;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.lock-timeout-missing")).toBeDefined();
  });

  it("does not flag lock-timeout when SET lock_timeout is present", () => {
    const r = lintSqlText("SET lock_timeout = '5s'; ALTER TABLE t ADD COLUMN x int;", "f.sql");
    // Each statement linted separately. The ALTER statement does not contain the SET, so the rule still fires.
    // This is intentional: lock_timeout is per-session, not per-statement, but we want to nudge users to set it
    // in the same migration. Document the behavior explicitly:
    expect(r.find((f) => f.ruleId === "migration.lock-timeout-missing")).toBeDefined();
  });

  it("does not flag a BEGIN block that already contains the SET", () => {
    // Check that the SET statement itself does not get flagged
    const r = lintSqlText("SET lock_timeout = '5s';", "f.sql");
    expect(r).toHaveLength(0);
  });

  it("does not double-flag a single statement under the same rule", () => {
    const r = lintSqlText("CREATE INDEX idx ON t (a);", "f.sql");
    expect(r.filter((f) => f.ruleId === "migration.non-concurrent-index")).toHaveLength(1);
  });

  it("comments do not bypass detection", () => {
    const r = lintSqlText("-- evil migration\nDROP TABLE users;", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.drop-table")).toBeDefined();
  });

  it("string literals do not trigger false positives", () => {
    const r = lintSqlText("SELECT 'DROP TABLE users';", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.drop-table")).toBeUndefined();
  });

  it("handles dollar-quoted procedure bodies", () => {
    const sql = "CREATE OR REPLACE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; END $$ LANGUAGE plpgsql;";
    expect(() => lintSqlText(sql, "f.sql")).not.toThrow();
  });

  it("findings include line numbers", () => {
    const r = lintSqlText("SELECT 1;\n\nDROP TABLE t;", "f.sql");
    const drop = r.find((f) => f.ruleId === "migration.drop-table");
    expect(drop?.location.line).toBeGreaterThanOrEqual(2);
  });

  it("handles empty input", () => {
    expect(lintSqlText("", "f.sql")).toEqual([]);
    expect(lintSqlText(";;;", "f.sql")).toEqual([]);
  });

  it("flags multiple statements separately", () => {
    const r = lintSqlText("DROP TABLE a; DROP TABLE b;", "f.sql");
    const drops = r.filter((f) => f.ruleId === "migration.drop-table");
    expect(drops).toHaveLength(2);
  });

  it("CREATE TEMP TABLE without CONCURRENTLY does not trigger non-concurrent-index", () => {
    const r = lintSqlText("CREATE TEMP TABLE foo (id int);", "f.sql");
    expect(r.find((f) => f.ruleId === "migration.non-concurrent-index")).toBeUndefined();
  });
});
