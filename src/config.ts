/**
 * Project configuration. A jimmy.config.json (or a path passed via --config)
 * lets a team set defaults without long command lines and tune the checks to
 * their schema conventions:
 *
 *   - failOn: default fail threshold (severity or per-category spec)
 *   - disabledRules: rule ids to drop from every report
 *   - tenantColumns: the column names that mark tenant ownership in this schema
 *   - publicRoles: roles treated as public-facing in the rls/rpc audits
 *   - roles: roles the rls fuzzer impersonates
 *   - jwtSubKey: the jwt claim key the fuzzer sets as the tenant identity
 *   - baseline: default baseline file path
 *
 * CLI flags always win over config. Config wins over built-in defaults.
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";

export const JimmyConfigSchema = z
  .object({
    failOn: z.string().optional(),
    disabledRules: z.array(z.string()).optional(),
    tenantColumns: z.array(z.string()).optional(),
    publicRoles: z.array(z.string()).optional(),
    roles: z.array(z.string()).optional(),
    jwtSubKey: z.string().optional(),
    baseline: z.string().optional(),
    customMigrationRules: z
      .array(
        z.object({
          id: z.string(),
          severity: z.enum(["info", "low", "medium", "high", "critical"]),
          title: z.string(),
          description: z.string(),
          pattern: z.string(),
        }),
      )
      .optional(),
  })
  .strict();

export type JimmyConfig = z.infer<typeof JimmyConfigSchema>;

export const DEFAULT_CONFIG_FILENAMES = ["jimmy.config.json", ".jimmyrc.json"];

/**
 * Load config from an explicit path, or auto-discover one of the default
 * filenames in the current working directory. Returns an empty config if none
 * is found. Throws a clear error on malformed or unknown-key config.
 */
export function loadConfig(explicitPath?: string, cwd = process.cwd()): JimmyConfig {
  let path: string | undefined;
  if (explicitPath) {
    path = resolve(cwd, explicitPath);
    if (!existsSync(path)) {
      throw new Error(`Config file not found: ${path}`);
    }
  } else {
    for (const name of DEFAULT_CONFIG_FILENAMES) {
      const candidate = resolve(cwd, name);
      if (existsSync(candidate)) {
        path = candidate;
        break;
      }
    }
  }
  if (!path) return {};

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf-8"));
  } catch (e) {
    throw new Error(`Could not parse config ${path}: ${(e as Error).message}`);
  }
  const parsed = JimmyConfigSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
    throw new Error(`Invalid config ${path}: ${issues}`);
  }
  return parsed.data;
}

/** Drop findings whose ruleId is in the disabled list. */
export function applyDisabledRules<T extends { ruleId: string }>(
  findings: T[],
  disabled: string[] | undefined,
): T[] {
  if (!disabled || disabled.length === 0) return findings;
  const set = new Set(disabled);
  return findings.filter((f) => !set.has(f.ruleId));
}
