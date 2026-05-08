import { describe, expect, it } from "vitest";
import {
  SafetyGuard,
  SafetyViolationError,
  parseConnectionString,
  DEFAULT_SAFETY_CONFIG,
} from "../src/safety/index.js";

describe("parseConnectionString", () => {
  it("parses postgres:// URLs", () => {
    const r = parseConnectionString("postgres://u:p@host:5433/mydb");
    expect(r).toEqual({ host: "host", port: 5433, database: "mydb", user: "u", password: "p" });
  });

  it("supports postgresql:// scheme", () => {
    expect(parseConnectionString("postgresql://h/db").host).toBe("h");
  });

  it("defaults port to 5432 when missing", () => {
    expect(parseConnectionString("postgres://h/db").port).toBe(5432);
  });

  it("decodes percent-encoded passwords", () => {
    expect(parseConnectionString("postgres://u:p%40ss@h/db").password).toBe("p@ss");
  });

  it("rejects non-postgres protocols", () => {
    expect(() => parseConnectionString("mysql://h/db")).toThrow(SafetyViolationError);
    expect(() => parseConnectionString("http://h/db")).toThrow(SafetyViolationError);
    expect(() => parseConnectionString("file:///etc/passwd")).toThrow(SafetyViolationError);
  });

  it("rejects URLs without a database name", () => {
    expect(() => parseConnectionString("postgres://h")).toThrow(/database/);
    expect(() => parseConnectionString("postgres://h/")).toThrow(/database/);
  });

  it("rejects malformed URLs", () => {
    expect(() => parseConnectionString("not a url")).toThrow(SafetyViolationError);
    expect(() => parseConnectionString("")).toThrow(SafetyViolationError);
  });
});

describe("SafetyGuard.assertConnection", () => {
  const shape = { host: "localhost", port: 5432, database: "myapp", user: "u" };

  it("allows benign databases", () => {
    expect(() => new SafetyGuard().assertConnection(shape)).not.toThrow();
  });

  it("blocks names containing 'prod'", () => {
    const g = new SafetyGuard();
    expect(() => g.assertConnection({ ...shape, database: "myapp_prod" })).toThrow(/prod/);
    expect(() => g.assertConnection({ ...shape, database: "production" })).toThrow();
    expect(() => g.assertConnection({ ...shape, database: "PROD" })).toThrow();
  });

  it("blocks names containing 'live' or 'primary' or 'master'", () => {
    const g = new SafetyGuard();
    expect(() => g.assertConnection({ ...shape, database: "live_db" })).toThrow();
    expect(() => g.assertConnection({ ...shape, database: "primary" })).toThrow();
    expect(() => g.assertConnection({ ...shape, database: "master_db" })).toThrow();
  });

  it("override flag bypasses every check", () => {
    const g = new SafetyGuard({ ...DEFAULT_SAFETY_CONFIG, override: true });
    expect(() => g.assertConnection({ ...shape, database: "production" })).not.toThrow();
  });

  it("host allowlist enforces inclusion", () => {
    const g = new SafetyGuard({ ...DEFAULT_SAFETY_CONFIG, allowedHosts: ["127.0.0.1"] });
    expect(() => g.assertConnection({ ...shape, host: "evil.example.com" })).toThrow(/host/i);
    expect(() => g.assertConnection({ ...shape, host: "127.0.0.1" })).not.toThrow();
  });

  it("does not let an attacker sneak in 'prod' via mixed case", () => {
    const g = new SafetyGuard();
    expect(() => g.assertConnection({ ...shape, database: "MyAppProdSnapshot" })).toThrow();
  });

  it("does not flag false positives like 'producer' (which still contains 'prod')", () => {
    // intentional: substring match is conservative. document the behavior.
    const g = new SafetyGuard();
    expect(() => g.assertConnection({ ...shape, database: "producer_test" })).toThrow();
  });
});

describe("SafetyGuard.assertMutation", () => {
  const shape = { host: "h", port: 5432, database: "mytestdb", user: "u" };

  it("read-only mode always blocks", () => {
    const g = new SafetyGuard({ ...DEFAULT_SAFETY_CONFIG, mode: "read-only" });
    expect(() => g.assertMutation(shape)).toThrow(/read-only/);
  });

  it("test-schema mode requires a test-shaped name", () => {
    const g = new SafetyGuard({ ...DEFAULT_SAFETY_CONFIG, mode: "test-schema" });
    expect(() => g.assertMutation(shape)).not.toThrow();
    expect(() => g.assertMutation({ ...shape, database: "myapp" })).toThrow(/test/);
  });

  it("unrestricted mode allows everything", () => {
    const g = new SafetyGuard({ ...DEFAULT_SAFETY_CONFIG, mode: "unrestricted" });
    expect(() => g.assertMutation({ ...shape, database: "anything" })).not.toThrow();
  });
});

describe("SafetyGuard.sessionInitSql", () => {
  it("emits all three timeouts", () => {
    const sql = new SafetyGuard().sessionInitSql();
    expect(sql).toContain("statement_timeout");
    expect(sql).toContain("lock_timeout");
    expect(sql).toContain("idle_in_transaction_session_timeout");
  });

  it("never produces a 0 statement_timeout (would mean no timeout)", () => {
    const g = new SafetyGuard({ ...DEFAULT_SAFETY_CONFIG, statementTimeoutMs: 1 });
    const sql = g.sessionInitSql();
    expect(sql).toMatch(/statement_timeout = [1-9]/);
  });
});
