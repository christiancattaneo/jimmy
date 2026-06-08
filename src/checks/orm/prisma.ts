/**
 * ORM cross-check (Prisma). Parses a schema.prisma and compares it against the
 * live database snapshot. The ORM and the database drift apart when a migration
 * is applied out of band, a model is edited without migrating, or a column is
 * changed directly: the app then assumes a shape the database does not have.
 *
 * Flags: a model whose table is missing, a field whose column is missing, and a
 * nullability mismatch (the sharpest one: the app treats a column as required
 * that the database allows to be null, or vice versa).
 *
 * The parser is intentionally lightweight (regex over model blocks). It handles
 * scalar fields, optional `?`, @map renames, and @@map table names. Relation
 * fields (a model type or an array) are not columns and are skipped.
 */

import type { SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding } from "../../report/findings.js";

interface PrismaField {
  name: string;
  column: string; // after @map
  optional: boolean;
  isScalarLike: boolean;
}

interface PrismaModel {
  model: string;
  table: string; // after @@map
  fields: PrismaField[];
}

const SCALAR_TYPES = new Set([
  "String",
  "Boolean",
  "Int",
  "BigInt",
  "Float",
  "Decimal",
  "DateTime",
  "Json",
  "Bytes",
]);

export function parsePrismaSchema(text: string): PrismaModel[] {
  // First pass: collect model and enum names so a field's type can be
  // classified. A field typed as a model is a relation (navigation object, not
  // a column); a field typed as an enum is a real column.
  const modelNames = new Set<string>();
  const enumNames = new Set<string>();
  for (const mm of text.matchAll(/\bmodel\s+(\w+)\s*\{/g)) modelNames.add(mm[1]!);
  for (const em of text.matchAll(/\benum\s+(\w+)\s*\{/g)) enumNames.add(em[1]!);

  const models: PrismaModel[] = [];
  const modelRe = /model\s+(\w+)\s*\{([\s\S]*?)\}/g;
  let m: RegExpExecArray | null;
  while ((m = modelRe.exec(text)) !== null) {
    const model = m[1]!;
    const body = m[2]!;
    let table = model.toLowerCase();
    const mapTable = body.match(/@@map\(\s*"([^"]+)"\s*\)/);
    if (mapTable) table = mapTable[1]!;

    const fields: PrismaField[] = [];
    for (const rawLine of body.split("\n")) {
      const line = rawLine.trim();
      if (!line || line.startsWith("//") || line.startsWith("@@")) continue;
      const fm = line.match(/^(\w+)\s+(\w+)(\?|\[\])?/);
      if (!fm) continue;
      const [, name, type, modifier] = fm;
      // A field is a column iff its type is a scalar or an enum. A list (`[]`),
      // an explicit @relation, or a field typed as another model is a relation
      // and maps to no column (the FK scalar is a separate field).
      const isColumn =
        modifier !== "[]" &&
        !/@relation\b/.test(line) &&
        (SCALAR_TYPES.has(type!) || enumNames.has(type!) || !modelNames.has(type!));
      if (!isColumn) continue;
      let column = name!;
      const colMap = line.match(/@map\(\s*"([^"]+)"\s*\)/);
      if (colMap) column = colMap[1]!;
      fields.push({ name: name!, column, optional: modifier === "?", isScalarLike: true });
    }
    models.push({ model, table, fields });
  }
  return models;
}

export function crossCheckPrisma(text: string, snapshot: SchemaSnapshot): Finding[] {
  const findings: Finding[] = [];
  const models = parsePrismaSchema(text);

  const tableByName = new Map(snapshot.tables.map((t) => [t.name.toLowerCase(), t]));
  const colByKey = new Map(snapshot.columns.map((c) => [`${c.table.toLowerCase()}.${c.name.toLowerCase()}`, c]));

  for (const model of models) {
    const table = tableByName.get(model.table.toLowerCase());
    if (!table) {
      findings.push({
        id: findingId("schema", "orm.missing-table", model.table),
        category: "schema",
        ruleId: "orm.missing-table",
        severity: "high",
        title: `Prisma model ${model.model} has no table in the database`,
        description: `The Prisma schema declares model ${model.model} (table ${model.table}) but the database has no such table. The ORM and the database have drifted; run migrations.`,
        location: { table: model.table },
      });
      continue;
    }
    for (const field of model.fields) {
      const col = colByKey.get(`${table.name.toLowerCase()}.${field.column.toLowerCase()}`);
      if (!col) {
        findings.push({
          id: findingId("schema", "orm.missing-column", `${model.table}.${field.column}`),
          category: "schema",
          ruleId: "orm.missing-column",
          severity: "high",
          title: `Prisma field ${model.model}.${field.name} has no column`,
          description: `Prisma expects column ${field.column} on ${table.schema}.${table.name}, but the database does not have it. Queries selecting this field will fail.`,
          location: { schema: table.schema, table: table.name, column: field.column },
        });
        continue;
      }
      // nullability mismatch: Prisma required (no ?) but column is nullable
      if (!field.optional && col.isNullable) {
        findings.push({
          id: findingId("schema", "orm.nullability-mismatch", `${model.table}.${field.column}`),
          category: "schema",
          ruleId: "orm.nullability-mismatch",
          severity: "medium",
          title: `Prisma treats ${model.model}.${field.name} as required but the column is nullable`,
          description: `Prisma declares ${field.name} non-optional, but ${table.schema}.${table.name}.${field.column} allows NULL. A NULL row will violate the app's type assumptions and can crash deserialization.`,
          location: { schema: table.schema, table: table.name, column: field.column },
          remediation: `ALTER TABLE ${table.schema}.${table.name} ALTER COLUMN ${field.column} SET NOT NULL; -- after backfilling`,
        });
      }
    }
  }

  return findings;
}
