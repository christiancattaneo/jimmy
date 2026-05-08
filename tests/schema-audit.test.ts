import { describe, expect, it } from "vitest";
import { auditSchema } from "../src/checks/schema/audit.js";
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
    ...partial,
  };
}

describe("auditSchema: no-primary-key", () => {
  it("flags tables with no PK", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.no-primary-key")).toBeDefined();
  });

  it("does not flag tables with a PK", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        uniques: [{ schema: "public", table: "t", name: "t_pk", columns: ["id"], isPrimaryKey: true }],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.no-primary-key")).toBeUndefined();
  });
});

describe("auditSchema: missing-fk", () => {
  it("flags _id columns without FK", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "orders", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "orders", name: "user_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.missing-fk")).toBeDefined();
  });

  it("does not flag the column 'id' itself", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "t", name: "id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.missing-fk")).toBeUndefined();
  });

  it("does not flag _id columns that have a FK constraint", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "orders", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "orders", name: "user_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
        foreignKeys: [
          { schema: "public", table: "orders", column: "user_id", referencedSchema: "public", referencedTable: "users", referencedColumn: "id", onDelete: "a", onUpdate: "a" },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.missing-fk")).toBeUndefined();
  });

  it("escalates severity for tenant_id", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "t", name: "tenant_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.missing-fk")?.severity).toBe("high");
  });
});

describe("auditSchema: weak-not-null", () => {
  it("flags nullable tenant_id", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "t", name: "tenant_id", ordinal: 1, dataType: "uuid", isNullable: true, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.weak-not-null")).toBeDefined();
  });

  it("does not flag non-nullable tenant_id", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "t", name: "tenant_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.weak-not-null")).toBeUndefined();
  });
});

describe("auditSchema: fk-no-index", () => {
  it("flags fk-shaped columns with no index", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "orders", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "orders", name: "user_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.fk-no-index")).toBeDefined();
  });

  it("does not flag when there is an index leading on the column", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "orders", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "orders", name: "user_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
        indexes: [
          {
            schema: "public",
            table: "orders",
            name: "orders_user_id_idx",
            definition: 'CREATE INDEX orders_user_id_idx ON public.orders USING btree (user_id)',
            isUnique: false,
            isPrimary: false,
          },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.fk-no-index")).toBeUndefined();
  });
});

describe("auditSchema: deterministic", () => {
  it("two runs produce identical findings", () => {
    const s = snapshot({
      tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
      columns: [
        { schema: "public", table: "t", name: "user_id", ordinal: 1, dataType: "uuid", isNullable: true, hasDefault: false, default: null },
      ],
    });
    const a = auditSchema(s).map((f) => f.id).sort();
    const b = auditSchema(s).map((f) => f.id).sort();
    expect(a).toEqual(b);
  });
});

describe("auditSchema: empty schema", () => {
  it("returns no findings on empty input", () => {
    expect(auditSchema(snapshot())).toEqual([]);
  });
});
