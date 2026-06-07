/**
 * Evidence redaction. Reports can be pasted into PRs, tickets, and chat. The
 * structural findings carry no data, but a few evidence fields echo SQL text
 * (migration statements, n+1 sample queries) that could contain literal values
 * like emails or ids. With --redact, jimmy masks string and number literals in
 * those text fields before writing the report.
 *
 * This is a privacy convenience, not a guarantee: it masks obvious literals,
 * not every conceivable leak. Structural fields (rule ids, table/column names,
 * counts) are left intact because they are the finding.
 */

import type { Finding } from "./findings.js";

/** Mask quoted string literals and standalone numbers in a SQL-ish string. */
export function redactSql(sql: string): string {
  return sql
    .replace(/'(?:''|[^'])*'/g, "'***'")
    .replace(/\b\d{2,}\b/g, "***");
}

const TEXT_EVIDENCE_KEYS = new Set(["statement", "sample", "query", "template", "detail"]);

function redactEvidence(evidence: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(evidence)) {
    if (typeof v === "string" && TEXT_EVIDENCE_KEYS.has(k)) {
      out[k] = redactSql(v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export function redactFindings(findings: Finding[]): Finding[] {
  return findings.map((f) =>
    f.evidence ? { ...f, evidence: redactEvidence(f.evidence) } : f,
  );
}
