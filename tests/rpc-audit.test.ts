import { describe, expect, it } from "vitest";
import { auditRpc } from "../src/checks/rls/rpc.js";
import type { FunctionInfo, SchemaSnapshot } from "../src/db/introspect.js";

function snapshot(functions: FunctionInfo[]): SchemaSnapshot {
  return {
    introspectedAt: "2026-06-07T00:00:00Z",
    tables: [],
    columns: [],
    foreignKeys: [],
    uniques: [],
    checks: [],
    policies: [],
    roles: [],
    indexes: [],
    functions,
  };
}

function fn(partial: Partial<FunctionInfo>): FunctionInfo {
  return {
    schema: "public",
    name: "do_thing",
    securityDefiner: true,
    owner: "postgres",
    hasSearchPath: true,
    executeRoles: [],
    arguments: "",
    ...partial,
  };
}

describe("auditRpc", () => {
  it("ignores non-definer functions entirely", () => {
    const f = auditRpc(snapshot([fn({ securityDefiner: false, executeRoles: ["anon"], hasSearchPath: false })]));
    expect(f).toHaveLength(0);
  });

  it("flags a definer function callable by anon", () => {
    const f = auditRpc(snapshot([fn({ executeRoles: ["anon"] })]));
    const pub = f.find((x) => x.ruleId === "rpc.definer-public");
    expect(pub?.severity).toBe("high");
  });

  it("flags a definer function callable by authenticated", () => {
    const f = auditRpc(snapshot([fn({ executeRoles: ["authenticated"] })]));
    expect(f.find((x) => x.ruleId === "rpc.definer-public")).toBeDefined();
  });

  it("treats default-acl (PUBLIC) as public-callable", () => {
    const f = auditRpc(snapshot([fn({ executeRoles: ["PUBLIC"] })]));
    expect(f.find((x) => x.ruleId === "rpc.definer-public")).toBeDefined();
  });

  it("does not flag definer-public when only service_role can execute", () => {
    const f = auditRpc(snapshot([fn({ executeRoles: ["service_role"] })]));
    expect(f.find((x) => x.ruleId === "rpc.definer-public")).toBeUndefined();
  });

  it("flags missing search_path on a definer function", () => {
    const f = auditRpc(snapshot([fn({ hasSearchPath: false, executeRoles: ["service_role"] })]));
    const sp = f.find((x) => x.ruleId === "rpc.definer-search-path");
    expect(sp?.severity).toBe("medium");
  });

  it("escalates missing search_path to high when also public-callable", () => {
    const f = auditRpc(snapshot([fn({ hasSearchPath: false, executeRoles: ["anon"] })]));
    expect(f.find((x) => x.ruleId === "rpc.definer-search-path")?.severity).toBe("high");
  });

  it("a locked-down definer (search_path pinned, service_role only) yields nothing", () => {
    const f = auditRpc(snapshot([fn({ hasSearchPath: true, executeRoles: ["service_role"] })]));
    expect(f).toHaveLength(0);
  });

  it("is deterministic", () => {
    const s = snapshot([fn({ executeRoles: ["anon"], hasSearchPath: false })]);
    expect(auditRpc(s).map((x) => x.id).sort()).toEqual(auditRpc(s).map((x) => x.id).sort());
  });
});
