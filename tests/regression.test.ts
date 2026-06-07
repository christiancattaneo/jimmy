import { describe, expect, it } from "vitest";
import { diffSnapshots } from "../src/checks/regression/diff.js";
import type { SchemaSnapshot, TableInfo, PolicyInfo, ColumnInfo, ForeignKeyInfo } from "../src/db/introspect.js";

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
const table = (name: string, rls: boolean, forced = false): TableInfo => ({ schema: "public", name, rlsEnabled: rls, rlsForced: forced, estimatedRows: 0 });
const policy = (table: string, name: string): PolicyInfo => ({ schema: "public", table, name, type: "PERMISSIVE", command: "ALL", roles: ["authenticated"], using: "true", withCheck: null });
const col = (table: string, name: string, nullable: boolean): ColumnInfo => ({ schema: "public", table, name, ordinal: 1, dataType: "text", isNullable: nullable, hasDefault: false, default: null });
const fk = (table: string, column: string): ForeignKeyInfo => ({ schema: "public", table, column, referencedSchema: "public", referencedTable: "users", referencedColumn: "id", onDelete: "a", onUpdate: "a" });

describe("diffSnapshots", () => {
  it("flags RLS turned off on an existing table", () => {
    const before = snap({ tables: [table("t", true)] });
    const after = snap({ tables: [table("t", false)] });
    const f = diffSnapshots(before, after);
    expect(f.find((x) => x.ruleId === "regress.rls-disabled")?.severity).toBe("critical");
  });

  it("flags RLS no longer forced", () => {
    const before = snap({ tables: [table("t", true, true)] });
    const after = snap({ tables: [table("t", true, false)] });
    expect(diffSnapshots(before, after).find((x) => x.ruleId === "regress.rls-unforced")).toBeDefined();
  });

  it("flags a removed policy on a surviving table", () => {
    const before = snap({ tables: [table("t", true)], policies: [policy("t", "p")] });
    const after = snap({ tables: [table("t", true)], policies: [] });
    expect(diffSnapshots(before, after).find((x) => x.ruleId === "regress.policy-removed")).toBeDefined();
  });

  it("does not flag a removed policy if the table was dropped too", () => {
    const before = snap({ tables: [table("t", true)], policies: [policy("t", "p")] });
    const after = snap({ tables: [], policies: [] });
    expect(diffSnapshots(before, after).find((x) => x.ruleId === "regress.policy-removed")).toBeUndefined();
  });

  it("flags a dropped foreign key", () => {
    const before = snap({ tables: [table("t", false)], foreignKeys: [fk("t", "user_id")] });
    const after = snap({ tables: [table("t", false)], foreignKeys: [] });
    expect(diffSnapshots(before, after).find((x) => x.ruleId === "regress.fk-dropped")).toBeDefined();
  });

  it("flags a column that became nullable", () => {
    const before = snap({ columns: [col("t", "x", false)] });
    const after = snap({ columns: [col("t", "x", true)] });
    expect(diffSnapshots(before, after).find((x) => x.ruleId === "regress.column-nullable")).toBeDefined();
  });

  it("is clean when nothing weakened", () => {
    const s = snap({ tables: [table("t", true, true)], policies: [policy("t", "p")], columns: [col("t", "x", false)] });
    expect(diffSnapshots(s, s)).toEqual([]);
  });

  it("does not flag a column that became MORE strict (nullable -> not null)", () => {
    const before = snap({ columns: [col("t", "x", true)] });
    const after = snap({ columns: [col("t", "x", false)] });
    expect(diffSnapshots(before, after)).toEqual([]);
  });
});
