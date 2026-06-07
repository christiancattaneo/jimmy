import { describe, expect, it } from "vitest";
import { redactSql, redactFindings } from "../src/report/redact.js";
import { findingId, type Finding } from "../src/report/findings.js";

describe("redactSql", () => {
  it("masks string literals", () => {
    expect(redactSql("WHERE email = 'alice@example.com'")).toBe("WHERE email = '***'");
  });
  it("masks multi-digit numbers but leaves single digits and identifiers", () => {
    expect(redactSql("WHERE id = 12345")).toBe("WHERE id = ***");
    expect(redactSql("LIMIT 1")).toBe("LIMIT 1");
  });
  it("handles escaped quotes", () => {
    expect(redactSql("x = 'it''s me'")).toBe("x = '***'");
  });
});

describe("redactFindings", () => {
  function f(evidence?: Record<string, unknown>): Finding {
    return {
      id: findingId("migrations", "r", "x"),
      category: "migrations",
      ruleId: "r",
      severity: "high",
      title: "t",
      description: "d",
      location: {},
      evidence,
    };
  }

  it("masks known text evidence keys", () => {
    const r = redactFindings([f({ statement: "INSERT INTO u VALUES ('secret@x.com', 42999)" })]);
    expect(r[0]!.evidence!.statement).toBe("INSERT INTO u VALUES ('***', ***)");
  });

  it("leaves structural evidence keys intact", () => {
    const r = redactFindings([f({ calls: 200, rowsAffected: 5, level: "READ COMMITTED" })]);
    expect(r[0]!.evidence).toEqual({ calls: 200, rowsAffected: 5, level: "READ COMMITTED" });
  });

  it("is a no-op for findings without evidence", () => {
    const r = redactFindings([f(undefined)]);
    expect(r[0]!.evidence).toBeUndefined();
  });
});
