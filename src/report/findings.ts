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

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export interface FailOnSpec {
  /** Default threshold for categories not explicitly named. */
  default: Severity;
  /** Per-category overrides. */
  byCategory: Partial<Record<CheckCategory, Severity>>;
}

/**
 * Parse a --fail-on value. Accepts a bare severity ("high") or a comma list of
 * `category=severity` pairs with an optional `default=severity`
 * (e.g. "default=high,rls-audit=medium,schema=low"). Bare category names like
 * "rls" expand to both rls-audit and rls-fuzz.
 */
export function parseFailOn(spec: string): FailOnSpec {
  const trimmed = spec.trim();
  if (!trimmed.includes("=")) {
    return { default: coerceSeverity(trimmed), byCategory: {} };
  }
  const result: FailOnSpec = { default: "high", byCategory: {} };
  for (const part of trimmed.split(",")) {
    const [rawKey, rawVal] = part.split("=").map((s) => s.trim());
    if (!rawKey || !rawVal) continue;
    const severity = coerceSeverity(rawVal);
    if (rawKey === "default") {
      result.default = severity;
      continue;
    }
    for (const cat of expandCategory(rawKey)) {
      result.byCategory[cat] = severity;
    }
  }
  return result;
}

function coerceSeverity(value: string): Severity {
  const v = value.toLowerCase() as Severity;
  if (!SEVERITIES.includes(v)) {
    throw new Error(`Invalid severity "${value}". Use one of: ${SEVERITIES.join(", ")}.`);
  }
  return v;
}

function expandCategory(key: string): CheckCategory[] {
  const all: CheckCategory[] = ["rls-audit", "rls-fuzz", "schema", "migrations", "anomalies", "nplusone"];
  if (all.includes(key as CheckCategory)) return [key as CheckCategory];
  if (key === "rls") return ["rls-audit", "rls-fuzz"];
  throw new Error(`Unknown category "${key}".`);
}

/** True if any finding meets or exceeds its category threshold. */
export function anyFails(findings: Finding[], spec: FailOnSpec): boolean {
  return findings.some((f) => {
    const threshold = spec.byCategory[f.category] ?? spec.default;
    return isAtOrAbove(f.severity, threshold);
  });
}

export function findingId(category: CheckCategory, ruleId: string, scope: string): string {
  const slug = `${category}:${ruleId}:${scope}`;
  let h = 0;
  for (let i = 0; i < slug.length; i++) {
    h = (h * 31 + slug.charCodeAt(i)) | 0;
  }
  return `JIMMY-${(h >>> 0).toString(16).padStart(8, "0").toUpperCase()}`;
}
