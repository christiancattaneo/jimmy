/**
 * Report generation. Markdown and JSON. Stable, deterministic ordering so
 * reruns produce diffable output.
 */

import { SEVERITY_ORDER, type Finding, type Severity } from "./findings.js";

export interface ReportConfig {
  title: string;
  target: string;
  generatedAt?: string;
}

export interface ReportStats {
  total: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
}

export interface JimmyReport {
  config: ReportConfig;
  stats: ReportStats;
  findings: Finding[];
}

export function buildReport(findings: Finding[], config: Omit<ReportConfig, "generatedAt">): JimmyReport {
  const sorted = [...findings].sort((a, b) => {
    const sd = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (sd !== 0) return sd;
    if (a.category !== b.category) return a.category.localeCompare(b.category);
    if (a.ruleId !== b.ruleId) return a.ruleId.localeCompare(b.ruleId);
    return a.id.localeCompare(b.id);
  });
  const bySeverity: Record<Severity, number> = {
    info: 0, low: 0, medium: 0, high: 0, critical: 0,
  };
  const byCategory: Record<string, number> = {};
  for (const f of sorted) {
    bySeverity[f.severity] += 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }
  return {
    config: { ...config, generatedAt: new Date().toISOString() },
    stats: { total: sorted.length, bySeverity, byCategory },
    findings: sorted,
  };
}

export function reportToJson(report: JimmyReport): string {
  return JSON.stringify(report, null, 2);
}

/** Map jimmy severity to SARIF result level. */
function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

/** SARIF security-severity score (GitHub uses it to bucket alerts). */
function securitySeverity(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.0";
    case "low":
      return "3.0";
    default:
      return "0.0";
  }
}

/**
 * SARIF 2.1.0 for GitHub code scanning. Findings with a file location point at
 * that file; database findings get a synthetic, stable uri so each result
 * still carries a location (GitHub requires one).
 */
export function reportToSarif(report: JimmyReport): string {
  const ruleIds = [...new Set(report.findings.map((f) => f.ruleId))].sort();
  const rules = ruleIds.map((id) => {
    const sample = report.findings.find((f) => f.ruleId === id)!;
    return {
      id,
      name: id.replace(/[^a-zA-Z0-9]/g, ""),
      shortDescription: { text: sample.title },
      defaultConfiguration: { level: sarifLevel(sample.severity) },
      properties: { category: sample.category, "security-severity": securitySeverity(sample.severity) },
    };
  });

  const results = report.findings.map((f) => {
    const uri = f.location.file
      ? toUri(f.location.file)
      : `db/${f.location.schema ?? "database"}/${f.location.table ?? f.location.role ?? "object"}`;
    const region = f.location.line ? { startLine: Math.max(1, f.location.line) } : { startLine: 1 };
    return {
      ruleId: f.ruleId,
      level: sarifLevel(f.severity),
      message: { text: `${f.title}. ${f.description}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region,
          },
        },
      ],
      partialFingerprints: { jimmyFindingId: f.id },
      properties: { severity: f.severity, category: f.category },
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "jimmy",
            informationUri: "https://github.com/christiancattaneo/jimmy",
            version: "0.1.0",
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function toUri(filePath: string): string {
  // SARIF uris are relative paths with forward slashes; strip a leading slash.
  return filePath.replace(/\\/g, "/").replace(/^\//, "");
}

// reportToSarif is defined above.

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEV_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#8b8b96",
};

/** Self-contained dark HTML report; no external assets. */
export function reportToHtml(report: JimmyReport): string {
  const sevBadges = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map(
      (s) =>
        `<span class="sev" style="--c:${SEV_COLOR[s]}">${s} ${report.stats.bySeverity[s]}</span>`,
    )
    .join("");

  const findingsHtml = report.findings
    .map((f) => {
      const loc = [f.location.schema, f.location.table, f.location.column].filter(Boolean).join(".");
      const file = f.location.file ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : "";
      return `<article class="finding" style="--c:${SEV_COLOR[f.severity]}">
  <h3><span class="badge" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span> ${escapeHtml(f.title)}</h3>
  <p class="meta"><code>${escapeHtml(f.ruleId)}</code>${loc ? ` &middot; <code>${escapeHtml(loc)}</code>` : ""}${f.location.role ? ` &middot; role <code>${escapeHtml(f.location.role)}</code>` : ""}${file ? ` &middot; <code>${escapeHtml(file)}</code>` : ""}</p>
  <p>${escapeHtml(f.description)}</p>
  ${f.remediation ? `<pre class="fix">${escapeHtml(f.remediation)}</pre>` : ""}
</article>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(report.config.title)}</title>
<style>
  :root { color-scheme: dark; }
  body { background:#0a0a0f; color:#e4e4e7; font:15px/1.6 -apple-system,Inter,sans-serif; margin:0; padding:2rem; }
  .wrap { max-width:900px; margin:0 auto; }
  h1 { font-size:1.6rem; } h3 { font-size:1.05rem; margin:0 0 .4rem; }
  .target { color:#8b8b96; font-family:monospace; }
  .sev { display:inline-block; margin:.2rem .4rem .2rem 0; padding:.2rem .6rem; border-radius:999px; border:1px solid var(--c); color:var(--c); font-size:.8rem; }
  .finding { background:#12121a; border:1px solid #2a2a3a; border-left:3px solid var(--c); border-radius:10px; padding:1rem 1.2rem; margin:1rem 0; }
  .badge { color:#fff; padding:.1rem .5rem; border-radius:6px; font-size:.75rem; text-transform:uppercase; }
  .meta { color:#8b8b96; font-size:.85rem; } code { color:#a78bfa; }
  pre.fix { background:#0d0d14; border:1px solid #2a2a3a; border-radius:8px; padding:.8rem; overflow-x:auto; font-size:.82rem; white-space:pre-wrap; }
  .empty { color:#22c55e; }
</style></head>
<body><div class="wrap">
<h1>${escapeHtml(report.config.title)}</h1>
<p class="target">${escapeHtml(report.config.target)} &middot; ${report.config.generatedAt ?? ""}</p>
<p>${sevBadges}</p>
${report.findings.length === 0 ? '<p class="empty">No findings. The database looks well-locked from this angle.</p>' : findingsHtml}
</div></body></html>`;
}

export function reportToMarkdown(report: JimmyReport): string {
  const lines: string[] = [];
  lines.push(`# ${report.config.title}`);
  lines.push("");
  lines.push(`Target: \`${report.config.target}\``);
  lines.push(`Generated: ${report.config.generatedAt ?? new Date().toISOString()}`);
  lines.push("");
  lines.push(`## Summary`);
  lines.push("");
  lines.push(`Total findings: **${report.stats.total}**`);
  lines.push("");
  lines.push(`Severity breakdown:`);
  lines.push("");
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    lines.push(`- ${sev}: ${report.stats.bySeverity[sev]}`);
  }
  lines.push("");
  lines.push(`Category breakdown:`);
  lines.push("");
  for (const [cat, count] of Object.entries(report.stats.byCategory).sort()) {
    lines.push(`- ${cat}: ${count}`);
  }
  lines.push("");
  if (report.findings.length === 0) {
    lines.push(`## Findings`);
    lines.push("");
    lines.push("No findings. The database looks well-locked from this angle.");
    lines.push("");
    return lines.join("\n");
  }
  // Group findings by category; findings are already sorted by severity then
  // category then rule, so re-grouping keeps the most severe first within each.
  const byCategory = new Map<string, Finding[]>();
  for (const f of report.findings) {
    const arr = byCategory.get(f.category) ?? [];
    arr.push(f);
    byCategory.set(f.category, arr);
  }
  const orderedCategories = [...byCategory.keys()].sort();

  // Table of contents: one line per category with its finding count.
  lines.push(`## Findings`);
  lines.push("");
  for (const cat of orderedCategories) {
    const count = byCategory.get(cat)!.length;
    lines.push(`- [${CATEGORY_TITLES[cat] ?? cat}](#${anchor(cat)}) (${count})`);
  }
  lines.push("");

  for (const cat of orderedCategories) {
    lines.push(`## ${CATEGORY_TITLES[cat] ?? cat}`);
    lines.push("");
    for (const f of byCategory.get(cat)!) {
      lines.push(`### ${f.id} [${f.severity}] ${f.title}`);
      lines.push("");
      lines.push(`**Rule**: \`${f.ruleId}\``);
      if (f.location.schema || f.location.table || f.location.column) {
        const parts = [f.location.schema, f.location.table, f.location.column].filter(Boolean);
        lines.push(`**Location**: \`${parts.join(".")}\``);
      }
      if (f.location.role) lines.push(`**Role**: \`${f.location.role}\``);
      if (f.location.file) {
        const loc = f.location.line ? `${f.location.file}:${f.location.line}` : f.location.file;
        lines.push(`**File**: \`${loc}\``);
      }
      lines.push("");
      lines.push(f.description);
      lines.push("");
      if (f.remediation) {
        lines.push("Remediation:");
        lines.push("");
        lines.push("```sql");
        lines.push(f.remediation);
        lines.push("```");
        lines.push("");
      }
      if (f.evidence) {
        lines.push("<details>");
        lines.push("<summary>evidence</summary>");
        lines.push("");
        lines.push("```json");
        lines.push(JSON.stringify(f.evidence, null, 2));
        lines.push("```");
        lines.push("");
        lines.push("</details>");
        lines.push("");
      }
    }
  }
  return lines.join("\n");
}

const CATEGORY_TITLES: Record<string, string> = {
  "rls-audit": "Row-level security",
  "rls-fuzz": "Tenant isolation (fuzz)",
  schema: "Schema integrity",
  migrations: "Migration safety",
  anomalies: "Transaction anomalies",
  nplusone: "N+1 queries",
};

/** GitHub-style markdown anchor for a heading derived from a category title. */
function anchor(category: string): string {
  const title = CATEGORY_TITLES[category] ?? category;
  return title
    .toLowerCase()
    .replace(/[^a-z0-9 -]/g, "")
    .replace(/ /g, "-");
}
