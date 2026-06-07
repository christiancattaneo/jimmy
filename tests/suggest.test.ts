import { describe, expect, it } from "vitest";
import { proposeProperties } from "../src/checks/suggest/propose.js";
import type { SchemaSnapshot, TableInfo, ColumnInfo, FunctionInfo } from "../src/db/introspect.js";

function snap(p: Partial<SchemaSnapshot>): SchemaSnapshot {
  return {
    introspectedAt: "t",
    tables: [],
    columns: [],
    grants: [],
    foreignKeys: [],
    uniques: [],
    checks: [],
    policies: [],
    roles: [],
    indexes: [],
    functions: [],
    ...p,
  };
}
const table = (name: string, rls: boolean): TableInfo => ({ schema: "public", name, rlsEnabled: rls, rlsForced: false, estimatedRows: 0 });
const col = (table: string, name: string): ColumnInfo => ({ schema: "public", table, name, ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null });

describe("proposeProperties", () => {
  it("suggests a tenant fuzz for an rls table with a tenant column", () => {
    const f = proposeProperties(snap({ tables: [table("orders", true)], columns: [col("orders", "tenant_id")] }));
    const s = f.find((x) => x.ruleId === "suggest.fuzz-tenant");
    expect(s).toBeDefined();
    expect(s!.remediation).toContain("rls fuzz");
  });

  it("suggests concurrency testing for balance/quantity columns", () => {
    const f = proposeProperties(snap({ tables: [table("wallets", false)], columns: [col("wallets", "balance")] }));
    expect(f.find((x) => x.ruleId === "suggest.anomaly-concurrency")).toBeDefined();
  });

  it("suggests an rpc audit when SECURITY DEFINER functions exist", () => {
    const fn: FunctionInfo = { schema: "public", name: "f", securityDefiner: true, owner: "postgres", hasSearchPath: false, executeRoles: ["anon"], arguments: "" };
    const f = proposeProperties(snap({ functions: [fn] }));
    expect(f.find((x) => x.ruleId === "suggest.rpc-audit")).toBeDefined();
  });

  it("falls back to a scan suggestion when nothing stands out", () => {
    const f = proposeProperties(snap({ tables: [table("plain", false)], columns: [col("plain", "label")] }));
    expect(f.map((x) => x.ruleId)).toEqual(["suggest.scan"]);
  });
});
