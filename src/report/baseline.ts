/**
 * Baseline support. A team adopting jimmy on an existing database does not
 * want to fix 2,892 findings before the first green build. A baseline records
 * the findings that exist today; subsequent runs only fail on findings that
 * are NOT in the baseline (i.e. newly introduced).
 *
 * The baseline is keyed by finding id, which is a stable hash of
 * (category, ruleId, scope). Moving a finding's line number does not change
 * its id, so a baseline survives reformatting. Genuinely new findings get new
 * ids and break the build.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Finding } from "./findings.js";

export interface Baseline {
  version: 1;
  generatedAt: string;
  /** Sorted list of accepted finding ids. */
  acceptedIds: string[];
}

export function buildBaseline(findings: Finding[]): Baseline {
  const ids = [...new Set(findings.map((f) => f.id))].sort();
  return { version: 1, generatedAt: new Date().toISOString(), acceptedIds: ids };
}

export function writeBaseline(path: string, findings: Finding[]): Baseline {
  const baseline = buildBaseline(findings);
  writeFileSync(path, JSON.stringify(baseline, null, 2));
  return baseline;
}

export function readBaseline(path: string): Baseline {
  if (!existsSync(path)) {
    throw new Error(`Baseline file not found: ${path}`);
  }
  const data = JSON.parse(readFileSync(path, "utf-8"));
  if (data.version !== 1 || !Array.isArray(data.acceptedIds)) {
    throw new Error(`Invalid baseline file: ${path}`);
  }
  return data as Baseline;
}

export interface BaselineApplication {
  /** Findings not present in the baseline (the ones that should fail the build). */
  newFindings: Finding[];
  /** Findings present in the baseline (suppressed). */
  baselined: Finding[];
  /** Baseline ids that no longer appear (the underlying issue was fixed). */
  resolvedIds: string[];
}

export function applyBaseline(findings: Finding[], baseline: Baseline): BaselineApplication {
  const accepted = new Set(baseline.acceptedIds);
  const seen = new Set<string>();
  const newFindings: Finding[] = [];
  const baselined: Finding[] = [];
  for (const f of findings) {
    seen.add(f.id);
    if (accepted.has(f.id)) baselined.push(f);
    else newFindings.push(f);
  }
  const resolvedIds = baseline.acceptedIds.filter((id) => !seen.has(id));
  return { newFindings, baselined, resolvedIds };
}
