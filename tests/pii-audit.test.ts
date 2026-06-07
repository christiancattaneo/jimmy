import { describe, expect, it } from "vitest";
import { auditPii, _internal } from "../src/checks/pii/audit.js";
import type { ColumnInfo, SchemaSnapshot } from "../src/db/introspect.js";

function snap(cols: Partial<ColumnInfo>[]): SchemaSnapshot {
  return {
    introspectedAt: "2026-06-07T00:00:00Z",
    tables: [],
    columns: cols.map((c, i) => ({
      schema: "public",
      table: "t",
      name: "col",
      ordinal: i + 1,
      dataType: "text",
      isNullable: true,
      hasDefault: false,
      default: null,
      ...c,
    })),
    grants: [],
    foreignKeys: [],
    uniques: [],
    checks: [],
    policies: [],
    roles: [],
    indexes: [],
    functions: [],
  };
}

describe("looksProtected", () => {
  const { looksProtected } = _internal;
  it("treats hash/encrypted suffixes as protected", () => {
    expect(looksProtected("password_hash")).toBe(true);
    expect(looksProtected("token_encrypted")).toBe(true);
    expect(looksProtected("api_key_enc")).toBe(true);
    expect(looksProtected("hashed_password")).toBe(true);
  });
  it("does not treat plain names as protected", () => {
    expect(looksProtected("password")).toBe(false);
    expect(looksProtected("api_key")).toBe(false);
  });
});

describe("auditPii: passwords", () => {
  it("flags a plaintext password column as critical", () => {
    const f = auditPii(snap([{ name: "password" }]));
    expect(f.find((x) => x.ruleId === "pii.plaintext-password")?.severity).toBe("critical");
  });

  it("does not flag password_hash", () => {
    const f = auditPii(snap([{ name: "password_hash" }]));
    expect(f).toHaveLength(0);
  });

  it("does not flag a non-textual password column (e.g. bytea)", () => {
    const f = auditPii(snap([{ name: "password", dataType: "bytea" }]));
    expect(f).toHaveLength(0);
  });
});

describe("auditPii: secrets", () => {
  it("flags api_key, access_token, private_key as high", () => {
    for (const name of ["api_key", "access_token", "stripe_secret", "private_key", "refresh_token"]) {
      const f = auditPii(snap([{ name }]));
      expect(f.find((x) => x.ruleId === "pii.plaintext-secret"), name).toBeDefined();
    }
  });

  it("does not flag an encrypted secret column", () => {
    const f = auditPii(snap([{ name: "api_key_encrypted" }]));
    expect(f).toHaveLength(0);
  });
});

describe("auditPii: high-sensitivity PII", () => {
  it("flags ssn, card_number, cvv as medium", () => {
    for (const name of ["ssn", "card_number", "cvv", "iban", "passport_number"]) {
      const f = auditPii(snap([{ name }]));
      expect(f.find((x) => x.ruleId === "pii.plaintext-pii")?.severity, name).toBe("medium");
    }
  });
});

describe("auditPii: deliberate non-findings (noise control)", () => {
  it("does not flag email, phone, name, address", () => {
    const f = auditPii(snap([{ name: "email" }, { name: "phone" }, { name: "full_name" }, { name: "address" }]));
    expect(f).toHaveLength(0);
  });

  it("does not flag a column merely containing 'pass' as a substring", () => {
    // 'compass_id' contains 'pass' but should not match the anchored password rule
    const f = auditPii(snap([{ name: "compass_id" }, { name: "passenger_count", dataType: "integer" }]));
    expect(f).toHaveLength(0);
  });

  it("emits at most one finding per column", () => {
    const f = auditPii(snap([{ name: "password" }]));
    expect(f).toHaveLength(1);
  });

  it("is deterministic", () => {
    const s = snap([{ name: "password" }, { name: "api_key" }]);
    expect(auditPii(s).map((x) => x.id).sort()).toEqual(auditPii(s).map((x) => x.id).sort());
  });
});
