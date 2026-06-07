/**
 * Property suggester. Reads the schema and proposes the highest-value checks to
 * run, each as a concrete jimmy command. This is the deterministic, reproducible
 * core of "AI property generation": the schema itself tells you what to test.
 *
 * Per jimmy's thesis (the verification side stays deterministic; generation
 * belongs on the input side), the suggestions are derived mechanically from the
 * schema, not invented by a model. An LLM could rank or enrich them, but the
 * pass/fail verdict must never depend on one, so the proposer is pure.
 *
 * Output is info-level findings whose remediation is the command to run.
 */

import type { SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding } from "../../report/findings.js";

const TENANT_COLS = ["tenant_id", "organization_id", "org_id", "workspace_id", "account_id", "user_id", "owner_id"];
const MONEY_HINTS = ["balance", "amount", "credits", "quantity", "stock", "inventory", "points"];

export function proposeProperties(snapshot: SchemaSnapshot): Finding[] {
  const out: Finding[] = [];
  const colsByTable = new Map<string, typeof snapshot.columns>();
  for (const c of snapshot.columns) {
    const k = `${c.schema}.${c.table}`;
    const arr = colsByTable.get(k) ?? [];
    arr.push(c);
    colsByTable.set(k, arr);
  }

  for (const t of snapshot.tables) {
    const key = `${t.schema}.${t.name}`;
    const cols = colsByTable.get(key) ?? [];
    const names = cols.map((c) => c.name.toLowerCase());

    if (t.rlsEnabled && names.some((n) => TENANT_COLS.includes(n))) {
      out.push(suggest("suggest.fuzz-tenant", "medium",
        `Fuzz tenant isolation on ${key}`,
        `${key} has RLS and a tenant column. Prove a tenant cannot reach another's rows.`,
        `jimmy rls fuzz --db $DATABASE_URL`, t.schema, t.name));
    }

    if (names.some((n) => MONEY_HINTS.some((h) => n.includes(h)))) {
      out.push(suggest("suggest.anomaly-concurrency", "medium",
        `Test concurrent updates on ${key}`,
        `${key} has a quantity/balance-like column where lost updates corrupt totals. Probe transaction anomalies and confirm your isolation level prevents lost update.`,
        `jimmy anomalies --db $DATABASE_URL --tests lost-update,write-skew`, t.schema, t.name));
    }
  }

  if (snapshot.functions.some((f) => f.securityDefiner)) {
    out.push(suggest("suggest.rpc-audit", "medium",
      `Audit SECURITY DEFINER functions`,
      `The schema has SECURITY DEFINER functions, the most common RLS bypass. Audit who can call them and whether their search_path is pinned.`,
      `jimmy rls audit --db $DATABASE_URL`, undefined, undefined));
  }

  if (out.length === 0) {
    out.push(suggest("suggest.scan", "info",
      "Run a full read-only scan",
      "No high-signal property stood out from the schema. Start with a full scan.",
      `jimmy scan --db $DATABASE_URL`, undefined, undefined));
  }
  return out;
}

function suggest(rule: string, severity: Finding["severity"], title: string, description: string, command: string, schema?: string, table?: string): Finding {
  return {
    id: findingId("rls-audit", rule, `${schema ?? ""}.${table ?? rule}`),
    category: "rls-audit",
    ruleId: rule,
    severity,
    title,
    description,
    location: schema ? { schema, table } : {},
    remediation: command,
  };
}
