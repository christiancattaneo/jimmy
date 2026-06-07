import { describe, expect, it } from "vitest";
import { auditRls, _internal } from "../src/checks/rls/audit.js";
import type { SchemaSnapshot } from "../src/db/introspect.js";

function snapshot(partial: Partial<SchemaSnapshot> = {}): SchemaSnapshot {
  return {
    introspectedAt: "2026-05-08T00:00:00Z",
    tables: [],
    columns: [],
    foreignKeys: [],
    uniques: [],
    checks: [],
    policies: [],
    roles: [],
    indexes: [],
    functions: [],
    ...partial,
  };
}

describe("isTriviallyTrue", () => {
  const { isTriviallyTrue } = _internal;
  it("matches plain true", () => {
    expect(isTriviallyTrue("true")).toBe(true);
    expect(isTriviallyTrue("(true)")).toBe(true);
    expect(isTriviallyTrue("1=1")).toBe(true);
    expect(isTriviallyTrue("1 = 1")).toBe(true);
    expect(isTriviallyTrue("(1=1)")).toBe(true);
    expect(isTriviallyTrue("(1 = 1)")).toBe(true);
  });
  it("does not match policies that look almost-true", () => {
    expect(isTriviallyTrue("true and tenant_id = auth.uid()")).toBe(false);
    expect(isTriviallyTrue("(false)")).toBe(false);
    expect(isTriviallyTrue("1=2")).toBe(false);
    expect(isTriviallyTrue(null)).toBe(false);
  });
  it("ignores leading/trailing whitespace", () => {
    expect(isTriviallyTrue("  true  ")).toBe(true);
  });
});

describe("clauseReferencesAny", () => {
  const { clauseReferencesAny } = _internal;
  it("matches exact column references", () => {
    expect(clauseReferencesAny("tenant_id = auth.uid()", ["tenant_id"])).toBe(true);
  });
  it("does not match prefix collisions", () => {
    expect(clauseReferencesAny("other_tenant_id = 1", ["tenant_id"])).toBe(false);
    expect(clauseReferencesAny("my_tenant_id_secret = 1", ["tenant_id"])).toBe(false);
  });
  it("returns false for null", () => {
    expect(clauseReferencesAny(null, ["x"])).toBe(false);
  });
});

describe("auditRls: rls.disabled", () => {
  it("flags any table with rls disabled", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "users", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
      }),
    );
    expect(f.length).toBe(1);
    expect(f[0]!.ruleId).toBe("rls.disabled");
  });

  it("escalates severity when tenant column is present", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "orders", rlsEnabled: false, rlsForced: false, estimatedRows: 1000 }],
        columns: [
          { schema: "public", table: "orders", name: "tenant_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f[0]!.severity).toBe("critical");
  });
});

describe("auditRls: rls.permissive-true", () => {
  it("flags PERMISSIVE policy with USING (true)", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "secrets", rlsEnabled: true, rlsForced: true, estimatedRows: 0 }],
        policies: [
          {
            schema: "public",
            table: "secrets",
            name: "wide_open",
            type: "PERMISSIVE",
            command: "SELECT",
            roles: ["authenticated"],
            using: "true",
            withCheck: null,
          },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.permissive-true")?.severity).toBe("critical");
  });

  it("does not flag RESTRICTIVE policy with USING (true)", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: true, rlsForced: true, estimatedRows: 0 }],
        policies: [
          {
            schema: "public",
            table: "t",
            name: "p",
            type: "RESTRICTIVE",
            command: "SELECT",
            roles: ["authenticated"],
            using: "true",
            withCheck: null,
          },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.permissive-true")).toBeUndefined();
  });
});

describe("auditRls: rls.tenant-no-filter", () => {
  it("flags policies where tenant column exists but predicate ignores it", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "rows", rlsEnabled: true, rlsForced: true, estimatedRows: 1 }],
        columns: [
          { schema: "public", table: "rows", name: "tenant_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
        policies: [
          {
            schema: "public",
            table: "rows",
            name: "user_only",
            type: "PERMISSIVE",
            command: "SELECT",
            roles: ["authenticated"],
            using: "user_id = auth.uid()",
            withCheck: null,
          },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.tenant-no-filter")).toBeDefined();
  });

  it("does not flag policies that DO reference the tenant column", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "rows", rlsEnabled: true, rlsForced: true, estimatedRows: 1 }],
        columns: [
          { schema: "public", table: "rows", name: "tenant_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
        policies: [
          {
            schema: "public",
            table: "rows",
            name: "tenant_only",
            type: "PERMISSIVE",
            command: "SELECT",
            roles: ["authenticated"],
            using: "tenant_id = (auth.jwt() ->> 'sub')::uuid",
            withCheck: null,
          },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.tenant-no-filter")).toBeUndefined();
  });
});

describe("auditRls: rls.no-with-check", () => {
  it("flags INSERT policy without WITH CHECK", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: true, rlsForced: true, estimatedRows: 0 }],
        policies: [
          { schema: "public", table: "t", name: "p", type: "PERMISSIVE", command: "INSERT", roles: ["authenticated"], using: null, withCheck: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.no-with-check")).toBeDefined();
  });

  it("does not flag INSERT policy WITH CHECK present", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: true, rlsForced: true, estimatedRows: 0 }],
        policies: [
          { schema: "public", table: "t", name: "p", type: "PERMISSIVE", command: "INSERT", roles: ["authenticated"], using: null, withCheck: "tenant_id = auth.uid()" },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.no-with-check")).toBeUndefined();
  });
});

describe("auditRls: rls.bypass-role", () => {
  it("flags non-system roles with BYPASSRLS", () => {
    const f = auditRls(
      snapshot({
        roles: [{ name: "myapp_user", isSuperuser: false, canLogin: true, canBypassRls: true }],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.bypass-role")?.severity).toBe("high");
  });

  it("does not flag postgres or supabase_admin", () => {
    const f = auditRls(
      snapshot({
        roles: [
          { name: "postgres", isSuperuser: true, canLogin: true, canBypassRls: true },
          { name: "supabase_admin", isSuperuser: false, canLogin: true, canBypassRls: true },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.bypass-role")).toBeUndefined();
  });

  it("does not flag service_role (bypass is by design in supabase)", () => {
    const f = auditRls(
      snapshot({
        roles: [{ name: "service_role", isSuperuser: false, canLogin: false, canBypassRls: true }],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.bypass-role")).toBeUndefined();
  });
});

describe("auditRls: rls.enabled-no-policy", () => {
  it("flags rls-enabled tables with zero policies", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: true, rlsForced: true, estimatedRows: 0 }],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.enabled-no-policy")).toBeDefined();
  });
});

describe("auditRls: rls.not-forced", () => {
  it("flags rls-enabled but not forced", () => {
    const f = auditRls(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: true, rlsForced: false, estimatedRows: 0 }],
        policies: [
          { schema: "public", table: "t", name: "p", type: "PERMISSIVE", command: "SELECT", roles: ["authenticated"], using: "tenant_id = auth.uid()", withCheck: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "rls.not-forced")).toBeDefined();
  });
});

describe("auditRls: stable finding ids", () => {
  it("identical schemas yield identical finding ids", () => {
    const s = snapshot({
      tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
    });
    const a = auditRls(s);
    const b = auditRls(s);
    expect(a.map((f) => f.id).sort()).toEqual(b.map((f) => f.id).sort());
  });

  it("different tables yield different ids", () => {
    const a = auditRls(snapshot({ tables: [{ schema: "public", name: "a", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }] }));
    const b = auditRls(snapshot({ tables: [{ schema: "public", name: "b", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }] }));
    expect(a[0]!.id).not.toBe(b[0]!.id);
  });
});
