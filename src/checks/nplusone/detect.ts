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

export interface TraceEntry {
  requestId: string;
  query: string;
}

/**
 * Parse a request-tagged trace. Two accepted formats per line:
 *   - JSON object: {"requestId":"abc","query":"SELECT ..."}
 *   - TSV: <requestId>\t<sql>
 * Lines that match neither are skipped.
 */
export function parseTrace(text: string): TraceEntry[] {
  const out: TraceEntry[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("{")) {
      try {
        const o = JSON.parse(trimmed) as { requestId?: string; request_id?: string; query?: string; sql?: string };
        const requestId = o.requestId ?? o.request_id;
        const query = o.query ?? o.sql;
        if (requestId && query) out.push({ requestId, query });
      } catch {
        /* skip */
      }
      continue;
    }
    const tab = trimmed.indexOf("\t");
    if (tab > 0) {
      out.push({ requestId: trimmed.slice(0, tab), query: trimmed.slice(tab + 1) });
    }
  }
  return out;
}

export function readTrace(file: string): TraceEntry[] {
  return parseTrace(readFileSync(file, "utf-8"));
}

/**
 * The real N+1 signal: a single request executes the same query template many
 * times. Groups by request, then by template, and flags templates whose
 * per-request execution count exceeds the threshold in any request.
 */
export function detectNplusOneFromTrace(entries: TraceEntry[], opts: NplusoneOptions = {}): Finding[] {
  const threshold = opts.threshold ?? 10;
  // requestId -> template -> count
  const perReq = new Map<string, Map<string, number>>();
  const sampleByTemplate = new Map<string, string>();
  for (const e of entries) {
    const t = templatize(e.query);
    if (!sampleByTemplate.has(t)) sampleByTemplate.set(t, e.query);
    const reqMap = perReq.get(e.requestId) ?? new Map<string, number>();
    reqMap.set(t, (reqMap.get(t) ?? 0) + 1);
    perReq.set(e.requestId, reqMap);
  }

  // for each template, the worst per-request count and how many requests it hit
  const worst = new Map<string, { maxPerReq: number; requests: number }>();
  for (const reqMap of perReq.values()) {
    for (const [t, count] of reqMap) {
      const cur = worst.get(t) ?? { maxPerReq: 0, requests: 0 };
      cur.maxPerReq = Math.max(cur.maxPerReq, count);
      if (count > 1) cur.requests += 1;
      worst.set(t, cur);
    }
  }

  const findings: Finding[] = [];
  for (const [template, w] of worst) {
    if (w.maxPerReq < threshold) continue;
    const sev: Severity = w.maxPerReq > threshold * 5 ? "high" : "medium";
    findings.push({
      id: findingId("nplusone", "nplusone.per-request", template.slice(0, 64)),
      category: "nplusone",
      ruleId: "nplusone.per-request",
      severity: sev,
      title: `Query template executed ${w.maxPerReq} times in a single request`,
      description:
        `Template "${truncate(template, 160)}" ran up to ${w.maxPerReq} times within one request (across ${w.requests} requests). ` +
        `This is a true N+1: an outer fetch followed by one query per row. Replace with a JOIN, IN (...), or a dataloader.`,
      location: {},
      evidence: {
        sample: truncate(sampleByTemplate.get(template) ?? "", 400),
        template: truncate(template, 240),
        maxPerRequest: w.maxPerReq,
        affectedRequests: w.requests,
      },
    });
  }
  return findings;
}
