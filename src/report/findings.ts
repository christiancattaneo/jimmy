/**
 * Shared finding type. Every check produces findings, the report assembles
 * them into a single document.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type CheckCategory =
  | "rls-audit"
  | "rls-fuzz"
  | "schema"
  | "migrations"
  | "anomalies"
  | "nplusone";

export interface Finding {
  /** Stable id derived from category + ruleId + scope so reruns dedup. */
  id: string;
  category: CheckCategory;
  /** Short rule id like `rls.disabled` or `schema.missing-fk`. */
  ruleId: string;
  severity: Severity;
  title: string;
  /** One paragraph human description. */
  description: string;
  /** Where in the database/code this applies. */
  location: {
    schema?: string;
    table?: string;
    column?: string;
    role?: string;
    file?: string;
    line?: number;
  };
  /** Optional remediation snippet, usually SQL. */
  remediation?: string;
  /** Free-form structured evidence the check captured. */
  evidence?: Record<string, unknown>;
}

export function isAtOrAbove(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

export function findingId(category: CheckCategory, ruleId: string, scope: string): string {
  const slug = `${category}:${ruleId}:${scope}`;
  let h = 0;
  for (let i = 0; i < slug.length; i++) {
    h = (h * 31 + slug.charCodeAt(i)) | 0;
  }
  return `JIMMY-${(h >>> 0).toString(16).padStart(8, "0").toUpperCase()}`;
}
