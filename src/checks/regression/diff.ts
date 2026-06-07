/**
 * Schema-regression diff. Compares a saved schema snapshot against the current
 * one and flags security regressions: a table that lost RLS, a policy that was
 * removed, a foreign key dropped, or a column that became nullable. Run it in
 * CI against a committed baseline snapshot so a migration cannot silently
 * weaken the database's guarantees.
 *
 * Pure: both snapshots are introspection output, no database access here.
 */

import type { SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding } from "../../report/findings.js";

function tableKey(schema: string, name: string): string {
  return `${schema}.${name}`;
}

export function diffSnapshots(before: SchemaSnapshot, after: SchemaSnapshot): Finding[] {
  const findings: Finding[] = [];

  const afterTables = new Map(after.tables.map((t) => [tableKey(t.schema, t.name), t]));
  const beforeTables = new Map(before.tables.map((t) => [tableKey(t.schema, t.name), t]));

  // RLS turned off on a table that previously had it
  for (const [key, bt] of beforeTables) {
    const at = afterTables.get(key);
    if (!at) continue; // dropped table is its own concern, not a weakening of access on an existing one
    if (bt.rlsEnabled && !at.rlsEnabled) {
      findings.push({
        id: findingId("rls-audit", "regress.rls-disabled", key),
        category: "rls-audit",
        ruleId: "regress.rls-disabled",
        severity: "critical",
        title: `RLS was turned off on ${key}`,
        description: `${key} had row-level security enabled in the baseline snapshot and now does not. A migration removed tenant isolation from this table.`,
        location: { schema: bt.schema, table: bt.name },
        remediation: `ALTER TABLE ${key} ENABLE ROW LEVEL SECURITY;`,
      });
    }
    if (bt.rlsForced && at.rlsEnabled && !at.rlsForced) {
      findings.push({
        id: findingId("rls-audit", "regress.rls-unforced", key),
        category: "rls-audit",
        ruleId: "regress.rls-unforced",
        severity: "high",
        title: `RLS is no longer FORCED on ${key}`,
        description: `${key} had FORCE ROW LEVEL SECURITY in the baseline and now does not, so the table owner bypasses RLS again.`,
        location: { schema: bt.schema, table: bt.name },
        remediation: `ALTER TABLE ${key} FORCE ROW LEVEL SECURITY;`,
      });
    }
  }

  // policies removed
  const policyKey = (p: { schema: string; table: string; name: string }) => `${p.schema}.${p.table}.${p.name}`;
  const afterPolicies = new Set(after.policies.map(policyKey));
  for (const p of before.policies) {
    if (!afterPolicies.has(policyKey(p))) {
      // only flag if the table still exists (otherwise the policy went with it)
      if (afterTables.has(tableKey(p.schema, p.table))) {
        findings.push({
          id: findingId("rls-audit", "regress.policy-removed", policyKey(p)),
          category: "rls-audit",
          ruleId: "regress.policy-removed",
          severity: "high",
          title: `Policy "${p.name}" was removed from ${p.schema}.${p.table}`,
          description: `The policy "${p.name}" (${p.command}) existed in the baseline and is gone. Confirm the access it granted is intentionally removed and not an accidental drop.`,
          location: { schema: p.schema, table: p.table },
        });
      }
    }
  }

  // foreign keys dropped
  const fkKey = (f: { schema: string; table: string; column: string }) => `${f.schema}.${f.table}.${f.column}`;
  const afterFks = new Set(after.foreignKeys.map(fkKey));
  for (const f of before.foreignKeys) {
    if (!afterFks.has(fkKey(f)) && afterTables.has(tableKey(f.schema, f.table))) {
      findings.push({
        id: findingId("schema", "regress.fk-dropped", fkKey(f)),
        category: "schema",
        ruleId: "regress.fk-dropped",
        severity: "medium",
        title: `Foreign key on ${f.schema}.${f.table}.${f.column} was dropped`,
        description: `The foreign key from ${f.schema}.${f.table}.${f.column} to ${f.referencedTable} existed in the baseline and is gone. Referential integrity for this column now lives only in application code.`,
        location: { schema: f.schema, table: f.table, column: f.column },
      });
    }
  }

  // columns that became nullable
  const colKey = (c: { schema: string; table: string; name: string }) => `${c.schema}.${c.table}.${c.name}`;
  const afterCols = new Map(after.columns.map((c) => [colKey(c), c]));
  for (const c of before.columns) {
    const ac = afterCols.get(colKey(c));
    if (ac && !c.isNullable && ac.isNullable) {
      findings.push({
        id: findingId("schema", "regress.column-nullable", colKey(c)),
        category: "schema",
        ruleId: "regress.column-nullable",
        severity: "medium",
        title: `${colKey(c)} became nullable`,
        description: `Column ${c.name} on ${c.schema}.${c.table} was NOT NULL in the baseline and is now nullable. Code that assumed it was always present may break.`,
        location: { schema: c.schema, table: c.table, column: c.name },
      });
    }
  }

  return findings;
}
