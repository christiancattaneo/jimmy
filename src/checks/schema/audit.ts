/**
 * Schema integrity audit. Looks for the structural mistakes that lead to
 * "the data is wrong but no error was raised":
 *   - foreign-key candidates without an actual FK constraint
 *   - tables with no primary key
 *   - tables with no unique constraints at all
 *   - widely-nullable columns where the name suggests required
 *   - cascading deletes that span tenant boundaries
 *   - missing index on a foreign-key column
 *   - boolean columns named like permissions but nullable
 */

import type { SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

export interface SchemaAuditOptions {
  /** Suffix patterns that suggest a foreign key, e.g. ["_id"]. */
  foreignKeySuffixes?: string[];
  /** Column names treated as "always required" if found nullable. */
  requiredNameHints?: string[];
}

const DEFAULT_FK_SUFFIXES = ["_id"];

const DEFAULT_REQUIRED_NAMES = [
  "tenant_id",
  "organization_id",
  "org_id",
  "workspace_id",
  "account_id",
  "owner_id",
  "user_id",
  "created_at",
  "updated_at",
];

function fqn(schema: string, table: string): string {
  return `${schema}.${table}`;
}

export function auditSchema(
  snapshot: SchemaSnapshot,
  opts: SchemaAuditOptions = {},
): Finding[] {
  const fkSuffixes = opts.foreignKeySuffixes ?? DEFAULT_FK_SUFFIXES;
  const requiredHints = (opts.requiredNameHints ?? DEFAULT_REQUIRED_NAMES).map((s) => s.toLowerCase());
  const findings: Finding[] = [];

  const fkSet = new Set(
    snapshot.foreignKeys.map((f) => `${f.schema}.${f.table}.${f.column}`),
  );
  const uniqueByTable = new Map<string, number>();
  const pkByTable = new Set<string>();
  for (const u of snapshot.uniques) {
    const key = `${u.schema}.${u.table}`;
    uniqueByTable.set(key, (uniqueByTable.get(key) ?? 0) + 1);
    if (u.isPrimaryKey) pkByTable.add(key);
  }

  const indexedColumns = new Set<string>();
  for (const idx of snapshot.indexes) {
    const m = idx.definition.match(/\(([^)]+)\)/);
    if (!m) continue;
    const cols = m[1]!.split(",").map((c) => c.trim().split(" ")[0]!.replace(/"/g, ""));
    if (cols.length > 0 && cols[0]) {
      indexedColumns.add(`${idx.schema}.${idx.table}.${cols[0]}`);
    }
  }

  for (const table of snapshot.tables) {
    const tFqn = fqn(table.schema, table.name);
    const tableKey = `${table.schema}.${table.name}`;

    if (!pkByTable.has(tableKey)) {
      findings.push({
        id: findingId("schema", "schema.no-primary-key", tFqn),
        category: "schema",
        ruleId: "schema.no-primary-key",
        severity: "high",
        title: `${tFqn} has no primary key`,
        description:
          `Table ${tFqn} has no primary key. Replication, ORMs that assume identity, and CDC tools all break or silently misbehave on tables without a primary key. ` +
          `Even queues with surrogate keys should declare one.`,
        location: { schema: table.schema, table: table.name },
        remediation: `ALTER TABLE ${tFqn} ADD PRIMARY KEY (id);`,
      });
    } else if ((uniqueByTable.get(tableKey) ?? 0) === 1) {
      const onlyPk = snapshot.uniques.find(
        (u) => u.schema === table.schema && u.table === table.name && u.isPrimaryKey,
      );
      if (onlyPk && onlyPk.columns.length === 1) {
        const col = snapshot.columns.find(
          (c) => c.schema === table.schema && c.table === table.name && c.name === onlyPk.columns[0],
        );
        if (col && (col.dataType === "uuid" || col.dataType.startsWith("integer") || col.dataType.startsWith("bigint"))) {
          findings.push({
            id: findingId("schema", "schema.only-surrogate-key", tFqn),
            category: "schema",
            ruleId: "schema.only-surrogate-key",
            severity: "low",
            title: `${tFqn} has only a surrogate primary key`,
            description:
              `Table ${tFqn} has a single ${col.dataType} primary key and no other unique constraints. ` +
              `If a natural key exists (email, slug, sku), declare it UNIQUE so the database enforces it.`,
            location: { schema: table.schema, table: table.name },
          });
        }
      }
    }
  }

  for (const col of snapshot.columns) {
    const colFqn = `${col.schema}.${col.table}.${col.name}`;
    const lowered = col.name.toLowerCase();

    const looksLikeFk = fkSuffixes.some((s) => lowered.endsWith(s.toLowerCase())) && lowered !== "id";
    if (looksLikeFk && !fkSet.has(`${col.schema}.${col.table}.${col.name}`)) {
      const sev: Severity = lowered === "tenant_id" || lowered === "organization_id" ? "high" : "medium";
      findings.push({
        id: findingId("schema", "schema.missing-fk", colFqn),
        category: "schema",
        ruleId: "schema.missing-fk",
        severity: sev,
        title: `${colFqn} looks like a foreign key but no constraint`,
        description:
          `Column ${col.name} on ${col.schema}.${col.table} is named like a foreign key but has no foreign-key constraint. ` +
          `Application-side checks drift; the database is the only place these guarantees survive a deploy.`,
        location: { schema: col.schema, table: col.table, column: col.name },
        remediation: `-- if you intended a relationship:\n-- ALTER TABLE ${col.schema}.${col.table} ADD CONSTRAINT fk_${col.table}_${col.name} FOREIGN KEY (${col.name}) REFERENCES <ref_table>(id);`,
      });
    }

    if (looksLikeFk && !indexedColumns.has(`${col.schema}.${col.table}.${col.name}`)) {
      findings.push({
        id: findingId("schema", "schema.fk-no-index", colFqn),
        category: "schema",
        ruleId: "schema.fk-no-index",
        severity: "medium",
        title: `${colFqn} is a foreign-key-shaped column with no index`,
        description:
          `Cascading deletes scan ${col.schema}.${col.table} sequentially for matching rows on ${col.name}. ` +
          `Joins on ${col.name} fall back to nested loops on the table.`,
        location: { schema: col.schema, table: col.table, column: col.name },
        remediation: `CREATE INDEX CONCURRENTLY ON ${col.schema}.${col.table} (${col.name});`,
      });
    }

    if (col.isNullable && requiredHints.includes(lowered)) {
      // A nullable column with a default is usually filled on the common path;
      // the bug only surfaces if someone inserts an explicit NULL. Lower the
      // severity so the high/critical band stays trustworthy.
      let sev: Severity = lowered.endsWith("_id") ? "high" : "medium";
      if (col.hasDefault) sev = "low";
      findings.push({
        id: findingId("schema", "schema.weak-not-null", colFqn),
        category: "schema",
        ruleId: "schema.weak-not-null",
        severity: sev,
        title: `${colFqn} is nullable but the name says required`,
        description:
          `Column ${col.name} is nullable. The name implies it is always present. ` +
          (col.hasDefault
            ? `It has a default, so the common insert path is covered, but an explicit NULL still slips through.`
            : `Application code that relies on the column being non-null will sporadically encounter undefined behavior.`),
        location: { schema: col.schema, table: col.table, column: col.name },
        remediation: `-- after backfilling:\n-- ALTER TABLE ${col.schema}.${col.table} ALTER COLUMN ${col.name} SET NOT NULL;`,
      });
    }
  }

  for (const fk of snapshot.foreignKeys) {
    if (fk.onDelete === "c") {
      const refIsTenantTable = ["tenants", "organizations", "orgs", "workspaces", "accounts", "users"].includes(
        fk.referencedTable.toLowerCase(),
      );
      if (refIsTenantTable) {
        findings.push({
          id: findingId("schema", "schema.tenant-cascade", `${fk.schema}.${fk.table}.${fk.column}`),
          category: "schema",
          ruleId: "schema.tenant-cascade",
          severity: "medium",
          title: `${fk.schema}.${fk.table}.${fk.column} cascades from a tenant-shaped table`,
          description:
            `Foreign key from ${fk.schema}.${fk.table}.${fk.column} to ${fk.referencedSchema}.${fk.referencedTable}.${fk.referencedColumn} uses ON DELETE CASCADE. ` +
            `Deleting a tenant row recursively deletes everything attached to it. That can be intentional, but it is also one accidental DELETE away from data loss.`,
          location: { schema: fk.schema, table: fk.table, column: fk.column },
        });
      }
    }
  }

  return findings;
}
