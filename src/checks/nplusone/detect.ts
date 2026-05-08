/**
 * N+1 detector. Reads pg_stat_statements (if installed) or a recorded log of
 * queries and groups them by template. Templates that fire many times for
 * a single primary query are flagged.
 *
 * Templating is conservative: numeric and string literals are replaced with
 * `?`, IN-lists are collapsed, dollar-style placeholders are kept as-is.
 */

import { readFileSync } from "node:fs";
import type { JimmyConnection } from "../../db/connect.js";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

export interface NplusoneOptions {
  /** Number of executions of a template above which the template is flagged. */
  threshold?: number;
  /** Minimum total time (ms) before a template is reported (filters noise). */
  minTotalMs?: number;
}

export interface QueryStat {
  query: string;
  template: string;
  calls: number;
  totalMs: number;
  meanMs: number;
}

export function templatize(sql: string): string {
  let s = sql.trim();
  s = s.replace(/--[^\n]*/g, "");
  s = s.replace(/\/\*[\s\S]*?\*\//g, "");
  s = s.replace(/'(?:''|[^'])*'/g, "?");
  s = s.replace(/\b\d+(\.\d+)?\b/g, "?");
  s = s.replace(/\bin\s*\(\s*(?:\?\s*,\s*)*\?\s*\)/gi, "IN (?)");
  s = s.replace(/\$\d+/g, "?");
  s = s.replace(/\s+/g, " ").trim().toLowerCase();
  return s;
}

export interface PgStatStatementsRow {
  query: string;
  calls: number;
  total_exec_time: number;
  mean_exec_time: number;
}

export async function pgStatStatementsAvailable(conn: JimmyConnection): Promise<boolean> {
  return conn.withClient(async (client) => {
    const r = await client.query(`SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'`);
    return (r.rowCount ?? 0) > 0;
  });
}

export async function readPgStatStatements(conn: JimmyConnection, limit = 5000): Promise<QueryStat[]> {
  return conn.withClient(async (client) => {
    const r = await client.query<PgStatStatementsRow>(
      `SELECT query, calls, total_exec_time, mean_exec_time FROM pg_stat_statements ORDER BY calls DESC LIMIT $1`,
      [limit],
    );
    return r.rows.map((row) => ({
      query: row.query,
      template: templatize(row.query),
      calls: Number(row.calls),
      totalMs: Number(row.total_exec_time),
      meanMs: Number(row.mean_exec_time),
    }));
  });
}

export function readQueryLog(file: string): QueryStat[] {
  const text = readFileSync(file, "utf-8");
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  const counts = new Map<string, { count: number; sample: string }>();
  for (const line of lines) {
    const sql = extractStatementFromLogLine(line);
    if (!sql) continue;
    const t = templatize(sql);
    const cur = counts.get(t);
    if (cur) {
      cur.count += 1;
    } else {
      counts.set(t, { count: 1, sample: sql });
    }
  }
  return Array.from(counts.entries()).map(([template, { count, sample }]) => ({
    query: sample,
    template,
    calls: count,
    totalMs: 0,
    meanMs: 0,
  }));
}

function extractStatementFromLogLine(line: string): string | null {
  const m = line.match(/(?:statement|execute|duration:[^:]*:)[^:]*:\s*(.+)$/i);
  if (m) return m[1] ?? null;
  if (/^(select|insert|update|delete|with)\s/i.test(line)) return line;
  return null;
}

export function detectNplusOne(stats: QueryStat[], opts: NplusoneOptions = {}): Finding[] {
  const threshold = opts.threshold ?? 50;
  const minTotalMs = opts.minTotalMs ?? 0;
  const findings: Finding[] = [];
  for (const s of stats) {
    if (s.calls < threshold) continue;
    if (s.totalMs > 0 && s.totalMs < minTotalMs) continue;
    const sev: Severity = s.calls > threshold * 10 ? "high" : "medium";
    findings.push({
      id: findingId("nplusone", "nplusone.template", s.template.slice(0, 64)),
      category: "nplusone",
      ruleId: "nplusone.template",
      severity: sev,
      title: `Repeated query template fired ${s.calls} times`,
      description:
        `Template "${truncate(s.template, 160)}" was executed ${s.calls} times` +
        (s.totalMs > 0 ? ` (total ${s.totalMs.toFixed(0)} ms, mean ${s.meanMs.toFixed(2)} ms).` : ".") +
        ` This is the canonical N+1 shape: a single outer fetch followed by one query per row. Replace with a JOIN, IN (...), or a dataloader.`,
      location: {},
      evidence: {
        sample: truncate(s.query, 400),
        template: truncate(s.template, 240),
        calls: s.calls,
        totalMs: s.totalMs,
        meanMs: s.meanMs,
      },
    });
  }
  return findings;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + "...";
}
