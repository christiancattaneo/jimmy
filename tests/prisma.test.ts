import { describe, expect, it } from "vitest";
import { parsePrismaSchema, crossCheckPrisma } from "../src/checks/orm/prisma.js";
import type { SchemaSnapshot } from "../src/db/introspect.js";

const SCHEMA = `
model User {
  id    String  @id @default(uuid())
  email String  @unique
  name  String?
  bio   String  @map("biography")
  posts Post[]
  @@map("users")
}

model Post {
  id     String @id
  title  String
}
`;

function snap(tables: { name: string; cols: { name: string; nullable: boolean }[] }[]): SchemaSnapshot {
  return {
    introspectedAt: "t",
    tables: tables.map((t) => ({ schema: "public", name: t.name, rlsEnabled: false, rlsForced: false, estimatedRows: 0 })),
    columns: tables.flatMap((t) =>
      t.cols.map((c, i) => ({ schema: "public", table: t.name, name: c.name, ordinal: i + 1, dataType: "text", isNullable: c.nullable, hasDefault: false, default: null })),
    ),
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

describe("parsePrismaSchema", () => {
  it("resolves @@map table names and @map column names, and skips relation lists", () => {
    const models = parsePrismaSchema(SCHEMA);
    const user = models.find((m) => m.model === "User")!;
    expect(user.table).toBe("users");
    const cols = user.fields.map((f) => f.column);
    expect(cols).toContain("email");
    expect(cols).toContain("biography"); // @map
    expect(cols).not.toContain("posts"); // relation list skipped
    expect(user.fields.find((f) => f.name === "name")?.optional).toBe(true);
  });

  it("defaults table name to the lowercased model when no @@map", () => {
    expect(parsePrismaSchema(SCHEMA).find((m) => m.model === "Post")!.table).toBe("post");
  });
});

describe("crossCheckPrisma", () => {
  it("flags a model whose table is missing", () => {
    const f = crossCheckPrisma(SCHEMA, snap([{ name: "users", cols: [{ name: "id", nullable: false }, { name: "email", nullable: false }, { name: "biography", nullable: false }] }]));
    // Post has no table
    expect(f.find((x) => x.ruleId === "orm.missing-table")).toBeDefined();
  });

  it("flags a field whose column is missing", () => {
    const f = crossCheckPrisma(SCHEMA, snap([
      { name: "users", cols: [{ name: "id", nullable: false }] }, // missing email, biography
      { name: "post", cols: [{ name: "id", nullable: false }, { name: "title", nullable: false }] },
    ]));
    expect(f.some((x) => x.ruleId === "orm.missing-column" && x.location.column === "email")).toBe(true);
  });

  it("flags a nullability mismatch (prisma required, column nullable)", () => {
    const f = crossCheckPrisma(SCHEMA, snap([
      { name: "users", cols: [{ name: "id", nullable: false }, { name: "email", nullable: true }, { name: "biography", nullable: false }] },
      { name: "post", cols: [{ name: "id", nullable: false }, { name: "title", nullable: false }] },
    ]));
    expect(f.some((x) => x.ruleId === "orm.nullability-mismatch" && x.location.column === "email")).toBe(true);
  });

  it("does not flag an optional prisma field backed by a nullable column", () => {
    const f = crossCheckPrisma(SCHEMA, snap([
      { name: "users", cols: [{ name: "id", nullable: false }, { name: "email", nullable: false }, { name: "name", nullable: true }, { name: "biography", nullable: false }] },
      { name: "post", cols: [{ name: "id", nullable: false }, { name: "title", nullable: false }] },
    ]));
    expect(f.some((x) => x.location.column === "name")).toBe(false);
  });
});
