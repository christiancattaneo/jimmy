/**
 * RLS property test. Mechanically enumerates the (table x role x op) matrix and
 * proves whether one synthetic tenant can touch another's data.
 *
 * Strategy:
 *   1. Pick two synthetic tenants A and B (uuids).
 *   2. For every table that has rls enabled and a tenant-like column, seed
 *      one row per tenant inside a SAVEPOINT.
 *   3. For each role under test (default: anon, authenticated), set the
 *      session role and a fake jwt claim, then attempt SELECT, UPDATE,
 *      DELETE, INSERT against the other tenant's row.
 *   4. Record outcomes deterministically. Any case where A touches B's row
 *      is a finding.
 *   5. ROLLBACK the whole thing.
 *
 * This is deterministic-on-output: the verdict is a pure function of the
 * recorded history, even though the seeding is randomized.
 *
 * IMPORTANT: this test is a strong best-effort probe. It cannot prove
 * correctness across schemas it cannot represent (e.g. policies that depend
 * on application-level state, custom claims with weird shapes, or rpc-only
 * paths). It catches the common bugs and reports honestly when it cannot.
 */

import type pg from "pg";
import { randomUUID } from "node:crypto";
import type { JimmyConnection } from "../../db/connect.js";
import type { ColumnInfo, SchemaSnapshot, TableInfo } from "../../db/introspect.js";
import { findingId, type Finding } from "../../report/findings.js";

type Client = pg.PoolClient;

export interface RlsFuzzOptions {
  /** Roles to impersonate. */
  roles?: string[];
  /** Names recognized as tenant-scoping columns. */
  tenantColumnNames?: string[];
  /** Skip tables matching these patterns. */
  skipTables?: string[];
  /** Maximum number of tables to probe. Tables are sampled by descending estimated row count. */
  maxTables?: number;
  /** When set, request claims include this jwt sub for tenant A. */
  jwtSubKey?: string;
}

const DEFAULT_TENANT_COLUMNS = [
  "tenant_id",
  "organization_id",
  "org_id",
  "workspace_id",
  "account_id",
  "company_id",
  "user_id",
  "owner_id",
];

const DEFAULT_ROLES = ["authenticated", "anon"];

interface ProbeOutcome {
  role: string;
  table: string;
  operation: "select" | "update" | "delete" | "insert-foreign";
  rowsAffected: number;
  errorCode?: string;
  errorMessage?: string;
}

interface SeedPlan {
  table: TableInfo;
  tenantColumn: string;
  primaryKey: string | null;
  primaryKeyDataType: string | null;
  columns: ColumnInfo[];
}

function isProbablyUuidColumn(col: ColumnInfo): boolean {
  const t = col.dataType.toLowerCase();
  return t === "uuid" || t === "text" || t.startsWith("character varying");
}

function pickPrimaryKey(snapshot: SchemaSnapshot, table: TableInfo): { name: string; dataType: string } | null {
  const pk = snapshot.uniques.find(
    (u) => u.schema === table.schema && u.table === table.name && u.isPrimaryKey,
  );
  if (!pk || pk.columns.length === 0) return null;
  const colName = pk.columns[0]!;
  const col = snapshot.columns.find(
    (c) => c.schema === table.schema && c.table === table.name && c.name === colName,
  );
  if (!col) return null;
  return { name: col.name, dataType: col.dataType };
}

function planSeeds(snapshot: SchemaSnapshot, opts: RlsFuzzOptions): SeedPlan[] {
  const tenantColumns = (opts.tenantColumnNames ?? DEFAULT_TENANT_COLUMNS).map((c) => c.toLowerCase());
  const skip = new Set((opts.skipTables ?? []).map((s) => s.toLowerCase()));
  const candidates: SeedPlan[] = [];

  for (const table of snapshot.tables) {
    if (!table.rlsEnabled) continue;
    const fqn = `${table.schema}.${table.name}`.toLowerCase();
    if (skip.has(fqn) || skip.has(table.name.toLowerCase())) continue;
    const cols = snapshot.columns.filter(
      (c) => c.schema === table.schema && c.table === table.name,
    );
    const tenantCol = cols.find((c) => tenantColumns.includes(c.name.toLowerCase()));
    if (!tenantCol) continue;
    if (!isProbablyUuidColumn(tenantCol)) continue;
    const pk = pickPrimaryKey(snapshot, table);
    candidates.push({
      table,
      tenantColumn: tenantCol.name,
      primaryKey: pk?.name ?? null,
      primaryKeyDataType: pk?.dataType ?? null,
      columns: cols,
    });
  }

  candidates.sort((a, b) => Number(b.table.estimatedRows) - Number(a.table.estimatedRows));
  if (opts.maxTables && opts.maxTables > 0) return candidates.slice(0, opts.maxTables);
  return candidates;
}

function defaultValueForColumn(col: ColumnInfo, fallbackId: string): string {
  if (col.hasDefault) {
    return "DEFAULT";
  }
  if (col.enumValues && col.enumValues.length > 0) {
    const label = col.enumValues[0]!.replace(/'/g, "''");
    return `'${label}'::${col.dataType}`;
  }
  const t = col.dataType.toLowerCase();
  if (t === "uuid") return `'${fallbackId}'::uuid`;
  if (t.startsWith("text") || t.startsWith("character") || t.startsWith("varchar"))
    return `'jimmy-probe-${fallbackId.slice(0, 8)}'`;
  if (t.startsWith("int") || t === "smallint" || t === "bigint") return "0";
  if (t === "boolean") return "false";
  if (t === "timestamp" || t === "timestamptz" || t.startsWith("timestamp"))
    return "now()";
  if (t === "date") return "now()::date";
  if (t === "jsonb") return "'{}'::jsonb";
  if (t === "json") return "'{}'::json";
  if (t === "numeric" || t === "double precision" || t === "real") return "0";
  return "NULL";
}

async function setRoleAndClaim(
  client: Client,
  role: string,
  tenantId: string,
  jwtSubKey: string,
): Promise<void> {
  await client.query(`RESET ROLE`);
  const claims = JSON.stringify({ sub: tenantId, [jwtSubKey]: tenantId, role });
  await client.query(`SELECT set_config('request.jwt.claims', $1, true)`, [claims]);
  await client.query(`SELECT set_config('role', $1, true)`, [role]);
  try {
    await client.query(`SET LOCAL ROLE ${quoteIdentifier(role)}`);
  } catch {
    /* role may not exist; we still recorded the claim */
  }
}

function quoteIdentifier(name: string): string {
  if (!/^[a-z_][a-z0-9_]*$/i.test(name)) {
    return `"${name.replace(/"/g, '""')}"`;
  }
  return `"${name}"`;
}

function fqi(schema: string, table: string): string {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(table)}`;
}

async function probe(
  client: Client,
  plan: SeedPlan,
  role: string,
  selfTenantId: string,
  otherTenantId: string,
  otherPkValue: unknown,
  jwtSubKey: string,
): Promise<ProbeOutcome[]> {
  const out: ProbeOutcome[] = [];
  const fqn = fqi(plan.table.schema, plan.table.name);
  const tenantCol = quoteIdentifier(plan.tenantColumn);

  await setRoleAndClaim(client, role, selfTenantId, jwtSubKey);

  const sp = `jimmy_probe_${randomUUID().replace(/-/g, "")}`;
  await client.query(`SAVEPOINT ${sp}`);
  try {
    try {
      const r = await client.query(`SELECT 1 FROM ${fqn} WHERE ${tenantCol} = $1 LIMIT 100`, [
        otherTenantId,
      ]);
      out.push({
        role,
        table: `${plan.table.schema}.${plan.table.name}`,
        operation: "select",
        rowsAffected: r.rowCount ?? 0,
      });
    } catch (e) {
      out.push(coerceErrorOutcome(role, plan, "select", e));
    }
    await rollbackTo(client, sp);

    if (plan.primaryKey && otherPkValue !== undefined && otherPkValue !== null) {
      try {
        const pk = quoteIdentifier(plan.primaryKey);
        const r = await client.query(
          `UPDATE ${fqn} SET ${tenantCol} = ${tenantCol} WHERE ${pk} = $1 RETURNING 1`,
          [otherPkValue],
        );
        out.push({
          role,
          table: `${plan.table.schema}.${plan.table.name}`,
          operation: "update",
          rowsAffected: r.rowCount ?? 0,
        });
      } catch (e) {
        out.push(coerceErrorOutcome(role, plan, "update", e));
      }
      await rollbackTo(client, sp);

      try {
        const pk = quoteIdentifier(plan.primaryKey);
        const r = await client.query(
          `DELETE FROM ${fqn} WHERE ${pk} = $1 RETURNING 1`,
          [otherPkValue],
        );
        out.push({
          role,
          table: `${plan.table.schema}.${plan.table.name}`,
          operation: "delete",
          rowsAffected: r.rowCount ?? 0,
        });
      } catch (e) {
        out.push(coerceErrorOutcome(role, plan, "delete", e));
      }
      await rollbackTo(client, sp);
    }

    try {
      const insertSql = buildInsertForTenant(plan, otherTenantId);
      const r = await client.query(insertSql);
      out.push({
        role,
        table: `${plan.table.schema}.${plan.table.name}`,
        operation: "insert-foreign",
        rowsAffected: r.rowCount ?? 0,
      });
    } catch (e) {
      out.push(coerceErrorOutcome(role, plan, "insert-foreign", e));
    }
    await rollbackTo(client, sp);
  } finally {
    await client.query(`RELEASE SAVEPOINT ${sp}`);
  }

  return out;
}

function coerceErrorOutcome(
  role: string,
  plan: SeedPlan,
  op: ProbeOutcome["operation"],
  e: unknown,
): ProbeOutcome {
  const err = e as { code?: string; message?: string };
  return {
    role,
    table: `${plan.table.schema}.${plan.table.name}`,
    operation: op,
    rowsAffected: 0,
    errorCode: err.code,
    errorMessage: err.message,
  };
}

/**
 * Enter replica mode so foreign-key trigger checks are skipped during seeding.
 * Returns true if it took effect. Only a superuser may change this setting, so
 * this is best-effort: if it fails we fall back to FK-respecting seeds (which
 * is why some tables still get skipped).
 */
async function trySuppressForeignKeys(client: Client): Promise<boolean> {
  try {
    await client.query(`SET LOCAL session_replication_role = replica`);
    return true;
  } catch {
    return false;
  }
}

async function tryRestoreForeignKeys(client: Client): Promise<void> {
  try {
    await client.query(`SET LOCAL session_replication_role = origin`);
  } catch {
    /* if we could set it we can unset it; ignore otherwise */
  }
}

async function rollbackTo(client: Client, sp: string): Promise<void> {
  try {
    await client.query(`ROLLBACK TO SAVEPOINT ${sp}`);
  } catch {
    /* connection may be in a bad state, caller will rollback the outer tx */
  }
}

function buildInsertForTenant(plan: SeedPlan, foreignTenantId: string): string {
  const cols: string[] = [];
  const vals: string[] = [];
  for (const c of plan.columns) {
    if (c.name === plan.tenantColumn) {
      cols.push(quoteIdentifier(c.name));
      vals.push(`'${foreignTenantId}'::${c.dataType}`);
      continue;
    }
    if (!c.hasDefault && !c.isNullable) {
      cols.push(quoteIdentifier(c.name));
      vals.push(defaultValueForColumn(c, randomUUID()));
    }
  }
  if (cols.length === 0) {
    return `INSERT INTO ${fqi(plan.table.schema, plan.table.name)} DEFAULT VALUES`;
  }
  return `INSERT INTO ${fqi(plan.table.schema, plan.table.name)} (${cols.join(", ")}) VALUES (${vals.join(", ")})`;
}

async function seedTenantRow(
  client: Client,
  plan: SeedPlan,
  tenantId: string,
): Promise<{ pkValue: unknown | null }> {
  const cols: string[] = [];
  const vals: string[] = [];
  let pkValue: unknown | null = null;

  for (const c of plan.columns) {
    if (c.name === plan.tenantColumn) {
      cols.push(quoteIdentifier(c.name));
      vals.push(`'${tenantId}'::${c.dataType}`);
      continue;
    }
    if (c.name === plan.primaryKey) {
      if (c.hasDefault) {
        cols.push(quoteIdentifier(c.name));
        vals.push("DEFAULT");
      } else if (c.dataType.toLowerCase() === "uuid") {
        const generated = randomUUID();
        pkValue = generated;
        cols.push(quoteIdentifier(c.name));
        vals.push(`'${generated}'::uuid`);
      } else {
        cols.push(quoteIdentifier(c.name));
        vals.push(defaultValueForColumn(c, randomUUID()));
      }
      continue;
    }
    if (!c.hasDefault && !c.isNullable) {
      cols.push(quoteIdentifier(c.name));
      vals.push(defaultValueForColumn(c, randomUUID()));
    }
  }

  // SQL-injection safety: every identifier here is wrapped by fqi()/
  // quoteIdentifier() (double-quoted, internal quotes doubled) and every value
  // in `vals` is either DEFAULT, a parameter-free literal that was escaped in
  // buildInsertForTenant/seedTenantRow, or a format_type cast (already quoted
  // by Postgres). Proven against hostile identifiers in
  // tests/integration/injection.test.ts (canary survives). Identifiers cannot
  // be bound parameters in SQL, so quoting is the correct defense.
  const sql =
    cols.length === 0
      ? `INSERT INTO ${fqi(plan.table.schema, plan.table.name)} DEFAULT VALUES${plan.primaryKey ? ` RETURNING ${quoteIdentifier(plan.primaryKey)}` : ""}`
      : `INSERT INTO ${fqi(plan.table.schema, plan.table.name)} (${cols.join(", ")}) VALUES (${vals.join(", ")})${plan.primaryKey ? ` RETURNING ${quoteIdentifier(plan.primaryKey)}` : ""}`;

  const result = await client.query(sql);
  if (plan.primaryKey && result.rows.length > 0) {
    const row = result.rows[0] as Record<string, unknown>;
    pkValue = row[plan.primaryKey] ?? pkValue;
  }
  return { pkValue };
}

export interface RlsFuzzResult {
  findings: Finding[];
  /** Every probe attempt, regardless of outcome. Useful for debugging. */
  history: ProbeOutcome[];
  /** Tables we wanted to probe but had to skip. */
  skipped: { table: string; reason: string }[];
}

export async function fuzzRls(
  conn: JimmyConnection,
  snapshot: SchemaSnapshot,
  opts: RlsFuzzOptions = {},
): Promise<RlsFuzzResult> {
  conn.guard.assertMutation(conn.shape);

  const roles = opts.roles ?? DEFAULT_ROLES;
  const jwtSubKey = opts.jwtSubKey ?? "sub";
  const tenantA = randomUUID();
  const tenantB = randomUUID();

  const plans = planSeeds(snapshot, opts);
  const findings: Finding[] = [];
  const history: ProbeOutcome[] = [];
  const skipped: { table: string; reason: string }[] = [];

  await conn.withRollback(async (client) => {
    await client.query(`SET LOCAL search_path TO public, pg_catalog`);

    for (const plan of plans) {
      const sp = `jimmy_seed_${randomUUID().replace(/-/g, "")}`;
      await client.query(`SAVEPOINT ${sp}`);
      try {
        await setRoleAndClaim(client, "postgres", tenantA, jwtSubKey);
        // Suppress FK trigger validation while seeding so we can seed a table
        // whose foreign keys point at parent tables we have not (and cannot)
        // seed (e.g. auth.users). Requires superuser; best-effort. Probing
        // runs with normal trigger semantics restored below.
        const fkSuppressed = await trySuppressForeignKeys(client);
        await seedTenantRow(client, plan, tenantA);
        const seededOther = await seedTenantRow(client, plan, tenantB);
        if (fkSuppressed) await tryRestoreForeignKeys(client);

        for (const role of roles) {
          const outcomes = await probe(
            client,
            plan,
            role,
            tenantA,
            tenantB,
            seededOther.pkValue,
            jwtSubKey,
          );
          history.push(...outcomes);
          for (const outcome of outcomes) {
            if (outcome.rowsAffected > 0) {
              findings.push(buildLeakFinding(plan, outcome));
            }
          }
        }
      } catch (e) {
        skipped.push({
          table: `${plan.table.schema}.${plan.table.name}`,
          reason: (e as Error).message,
        });
      } finally {
        await rollbackTo(client, sp);
        await client.query(`RELEASE SAVEPOINT ${sp}`).catch(() => undefined);
        await setRoleAndClaim(client, "postgres", tenantA, jwtSubKey);
      }
    }
  });

  // Surface skipped tables as info findings so the report is self-documenting
  // (no more guessing why a table was not probed).
  for (const s of skipped) {
    findings.push({
      id: findingId("rls-fuzz", "rls.fuzz.skipped", s.table),
      category: "rls-fuzz",
      ruleId: "rls.fuzz.skipped",
      severity: "info",
      title: `Could not fuzz ${s.table}`,
      description:
        `jimmy could not seed or probe ${s.table}, so its tenant isolation was not verified. ` +
        `This is a gap in coverage, not a clean result. Reason: ${s.reason}`,
      location: {
        schema: s.table.split(".")[0],
        table: s.table.split(".").slice(1).join("."),
      },
      evidence: { reason: s.reason },
    });
  }

  return { findings, history, skipped };
}

function buildLeakFinding(plan: SeedPlan, outcome: ProbeOutcome): Finding {
  const fqn = `${plan.table.schema}.${plan.table.name}`;
  const opLabel: Record<ProbeOutcome["operation"], string> = {
    select: "read",
    update: "modify",
    delete: "delete",
    "insert-foreign": "insert into the wrong tenant",
  };
  return {
    id: findingId("rls-fuzz", `rls.fuzz.${outcome.operation}`, `${fqn}.${outcome.role}`),
    category: "rls-fuzz",
    ruleId: `rls.fuzz.${outcome.operation}`,
    severity: "critical",
    title: `Tenant isolation broken: ${outcome.role} can ${opLabel[outcome.operation]} another tenant's row in ${fqn}`,
    description:
      `Role ${outcome.role} authenticated as tenant A successfully ran ${outcome.operation.toUpperCase()} ` +
      `against ${fqn} for tenant B's data. The policy on ${fqn} does not isolate tenants for this role.`,
    location: { schema: plan.table.schema, table: plan.table.name, role: outcome.role },
    remediation:
      `-- audit the policy USING/WITH CHECK on ${fqn} and confirm it filters on ${plan.tenantColumn}\n` +
      `-- pattern: USING ( ${plan.tenantColumn} = (auth.jwt() ->> 'sub')::uuid )`,
    evidence: { rowsAffected: outcome.rowsAffected, operation: outcome.operation },
  };
}

export const _internal = {
  isProbablyUuidColumn,
  defaultValueForColumn,
  buildInsertForTenant,
  planSeeds,
};
