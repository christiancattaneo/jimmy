import { describe, expect, it } from "vitest";
import { auditSchema } from "../src/checks/schema/audit.js";
import type { SchemaSnapshot } from "../src/db/introspect.js";

function snapshot(partial: Partial<SchemaSnapshot> = {}): SchemaSnapshot {
  return {
    introspectedAt: "2026-05-08T00:00:00Z",
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
  it("flags _id columns without FK (when a plausible referent table exists)", () => {
    const f = auditSchema(
      snapshot({
        tables: [
          { schema: "public", name: "orders", rlsEnabled: false, rlsForced: false, estimatedRows: 0 },
          { schema: "public", name: "users", rlsEnabled: false, rlsForced: false, estimatedRows: 0 },
        ],
        columns: [
          { schema: "public", table: "orders", name: "user_id", ordinal: 1, dataType: "uuid", isNullable: false, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.missing-fk")).toBeDefined();
  });

  it("does NOT flag an external-system id with no local referent table", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "inquiries", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "inquiries", name: "hubspot_contact_id", ordinal: 1, dataType: "text", isNullable: true, hasDefault: false, default: null },
          { schema: "public", table: "inquiries", name: "resend_email_id", ordinal: 2, dataType: "text", isNullable: true, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.missing-fk")).toBeUndefined();
    expect(f.find((x) => x.ruleId === "schema.fk-no-index")).toBeUndefined();
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
        tables: [
          { schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 },
          { schema: "public", name: "tenants", rlsEnabled: false, rlsForced: false, estimatedRows: 0 },
        ],
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

  it("downgrades weak-not-null to low when the column has a default", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "t", name: "created_at", ordinal: 1, dataType: "timestamptz", isNullable: true, hasDefault: true, default: "now()" },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.weak-not-null")?.severity).toBe("low");
  });

  it("keeps weak-not-null high for nullable _id columns without a default", () => {
    const f = auditSchema(
      snapshot({
        tables: [{ schema: "public", name: "t", rlsEnabled: false, rlsForced: false, estimatedRows: 0 }],
        columns: [
          { schema: "public", table: "t", name: "user_id", ordinal: 1, dataType: "uuid", isNullable: true, hasDefault: false, default: null },
        ],
      }),
    );
    expect(f.find((x) => x.ruleId === "schema.weak-not-null")?.severity).toBe("high");
  });
});

describe("auditSchema: fk-no-index", () => {
  it("flags fk-shaped columns with no index", () => {
    const f = auditSchema(
      snapshot({
        tables: [
          { schema: "public", name: "orders", rlsEnabled: false, rlsForced: false, estimatedRows: 0 },
          { schema: "public", name: "users", rlsEnabled: false, rlsForced: false, estimatedRows: 0 },
        ],
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
