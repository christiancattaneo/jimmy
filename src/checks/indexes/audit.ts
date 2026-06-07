/**
 * Index coverage. The schema audit flags foreign-key-shaped columns with no
 * index from the catalog; this check goes further and asks the planner. For
 * each tenant/foreign-key-shaped column on a table large enough to matter, it
 * runs EXPLAIN on a single-column equality lookup and flags a sequential scan.
 *
 * EXPLAIN (no ANALYZE) does not execute the query, so this is read-only and
 * cheap. It only probes columns that already exist, with a constant predicate.
 */

import type pg from "pg";
import type { ColumnInfo, SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

type Client = pg.PoolClient | pg.Client;

export interface IndexAuditOptions {
  /** Only probe tables whose estimated row count is at least this. */
  minRows?: number;
  /** Column-name suffixes/names worth probing. */
  lookupColumnNames?: string[];
  lookupSuffixes?: string[];
  /** Max number of EXPLAINs to run (safety cap). */
  maxProbes?: number;
}

const DEFAULT_LOOKUP_NAMES = [
  "tenant_id",
  "organization_id",
  "org_id",
  "workspace_id",
  "account_id",
  "user_id",
  "owner_id",
];

function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

function constantFor(col: ColumnInfo): string {
  const t = col.dataType.toLowerCase();
  if (t === "uuid") return `'00000000-0000-0000-0000-000000000000'::uuid`;
  if (t.startsWith("int") || t === "smallint" || t === "bigint") return "0";
  if (t.startsWith("text") || t.startsWith("character") || t.startsWith("varchar")) return "''";
  return "NULL";
}

export interface IndexAuditResult {
  findings: Finding[];
  probed: number;
}

export async function auditIndexes(
  client: Client,
  snapshot: SchemaSnapshot,
  opts: IndexAuditOptions = {},
): Promise<IndexAuditResult> {
  const minRows = opts.minRows ?? 1000;
  const names = (opts.lookupColumnNames ?? DEFAULT_LOOKUP_NAMES).map((n) => n.toLowerCase());
  const suffixes = (opts.lookupSuffixes ?? ["_id"]).map((s) => s.toLowerCase());
  const maxProbes = opts.maxProbes ?? 200;

  const findings: Finding[] = [];
  let probed = 0;

  const bigTables = new Set(
    snapshot.tables.filter((t) => Number(t.estimatedRows) >= minRows).map((t) => `${t.schema}.${t.name}`),
  );

  for (const col of snapshot.columns) {
    if (probed >= maxProbes) break;
    const tableKey = `${col.schema}.${col.table}`;
    if (!bigTables.has(tableKey)) continue;
    const lower = col.name.toLowerCase();
    const isLookup = names.includes(lower) || (suffixes.some((s) => lower.endsWith(s)) && lower !== "id");
    if (!isLookup) continue;

    const fqn = `${quoteIdent(col.schema)}.${quoteIdent(col.table)}`;
    const sql = `EXPLAIN (FORMAT JSON) SELECT 1 FROM ${fqn} WHERE ${quoteIdent(col.name)} = ${constantFor(col)}`;
    probed++;
    let plan: unknown;
    try {
      const r = await client.query(sql);
      plan = (r.rows[0] as Record<string, unknown>)["QUERY PLAN"];
    } catch {
      continue; // a column we cannot probe (odd type, permissions) is skipped
    }

    const planText = JSON.stringify(plan);
    // a top-level Seq Scan on a large table for an equality lookup means no
    // usable index. Index/Bitmap scans are fine.
    const usesSeqScan = /"Node Type":"Seq Scan"/.test(planText) && !/"Node Type":"Index/.test(planText);
    if (usesSeqScan) {
      const est = snapshot.tables.find((t) => `${t.schema}.${t.name}` === tableKey)?.estimatedRows ?? 0;
      const sev: Severity = lower === "tenant_id" || lower === "organization_id" ? "high" : "medium";
      findings.push({
        id: findingId("schema", "index.seq-scan-on-lookup", `${col.schema}.${col.table}.${col.name}`),
        category: "schema",
        ruleId: "index.seq-scan-on-lookup",
        severity: sev,
        title: `${col.schema}.${col.table}.${col.name} lookup uses a sequential scan`,
        description:
          `The planner chose a sequential scan for an equality lookup on ${col.name} in ${col.schema}.${col.table} (about ${est} rows). ` +
          `Every tenant query and every cascade on this column scans the whole table. Add an index.`,
        location: { schema: col.schema, table: col.table, column: col.name },
        remediation: `CREATE INDEX CONCURRENTLY ON ${col.schema}.${col.table} (${col.name});`,
        evidence: { estimatedRows: est },
      });
    }
  }

  return { findings, probed };
}
