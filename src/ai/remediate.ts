/**
 * AI remediation. Given jimmy's deterministic findings, ask Claude for concrete,
 * schema-aware fixes. The findings (the verdict) come from the deterministic
 * checks; the AI only authors the "here is how to fix it" prose and SQL. One
 * batched call per run, top findings only, to bound cost.
 */

import { askClaude, type AiResult } from "./client.js";
import type { Finding } from "../report/findings.js";

const MAX_FINDINGS = 20;

/** Build a compact prompt from the most severe findings. */
export function buildRemediationPrompt(findings: Finding[], target: string): string {
  const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const top = [...findings]
    .filter((f) => f.severity !== "info")
    .sort((a, b) => order[b.severity]! - order[a.severity]!)
    .slice(0, MAX_FINDINGS)
    .map((f) => {
      const loc = [f.location.schema, f.location.table, f.location.column].filter(Boolean).join(".");
      return `- [${f.severity}] ${f.ruleId} ${loc || f.location.role || ""}: ${f.title}`;
    })
    .join("\n");

  return `You are a Postgres and Supabase security expert reviewing findings from "jimmy", a database-layer auditor, for the database "${target}".

For each finding below, give a one-line explanation of the real-world risk and a concrete remediation (SQL where applicable, scoped to the table/column named). Be terse and specific. Do not restate the finding. Group by table. If a finding is commonly intentional (e.g. a public-forum table being world-readable), say so and how to confirm intent. Output plain markdown, no preamble.

Findings:
${top}`;
}

export interface RemediationResult extends AiResult {
  promptFindings: number;
}

export async function aiRemediate(
  findings: Finding[],
  target: string,
  opts: { apiKey?: string; model?: string } = {},
): Promise<RemediationResult> {
  const considered = findings.filter((f) => f.severity !== "info").slice(0, MAX_FINDINGS);
  const prompt = buildRemediationPrompt(findings, target);
  const result = await askClaude(prompt, opts);
  return { ...result, promptFindings: considered.length };
}
