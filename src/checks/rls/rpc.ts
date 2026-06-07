/**
 * RPC / SECURITY DEFINER audit. In Supabase, any function in an exposed schema
 * is callable over PostgREST as an rpc. A SECURITY DEFINER function runs with
 * the privileges of its owner (usually a superuser or a role that bypasses
 * RLS), so it is the single most common way RLS gets bypassed: an anon or
 * authenticated caller invokes a definer function that reads or writes data
 * the caller's own policies would never allow.
 *
 * Two compounding hazards:
 *   1. SECURITY DEFINER executable by anon/authenticated/PUBLIC.
 *   2. SECURITY DEFINER without a pinned search_path. An attacker who can
 *      create objects in a schema on the search_path can shadow a function or
 *      operator the definer calls, and have it run as the definer. CVE-class.
 */

import type { FunctionInfo, SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

export interface RpcAuditOptions {
  /** Roles whose execute access escalates severity. */
  publicRoles?: string[];
}

const DEFAULT_PUBLIC_ROLES = ["public", "anon", "authenticated"];

function callableByPublic(fn: FunctionInfo, publicRoles: Set<string>): string[] {
  return fn.executeRoles.filter((r) => publicRoles.has(r.toLowerCase()));
}

export function auditRpc(snapshot: SchemaSnapshot, opts: RpcAuditOptions = {}): Finding[] {
  const publicRoles = new Set((opts.publicRoles ?? DEFAULT_PUBLIC_ROLES).map((r) => r.toLowerCase()));
  const findings: Finding[] = [];

  for (const fn of snapshot.functions) {
    if (!fn.securityDefiner) continue;
    const fqn = `${fn.schema}.${fn.name}(${fn.arguments})`;
    const scope = `${fn.schema}.${fn.name}`;
    const exposedTo = callableByPublic(fn, publicRoles);

    if (exposedTo.length > 0) {
      findings.push({
        id: findingId("rls-audit", "rpc.definer-public", scope),
        category: "rls-audit",
        ruleId: "rpc.definer-public",
        severity: "high",
        title: `SECURITY DEFINER function ${scope} is callable by ${exposedTo.join(", ")}`,
        description:
          `Function ${fqn} runs as its owner (${fn.owner}) and is executable by [${exposedTo.join(", ")}]. ` +
          `Any logic inside it bypasses the caller's RLS. Confirm it validates auth.uid()/auth.jwt() itself and only touches rows the caller should reach, or revoke execute from public roles.`,
        location: { schema: fn.schema, table: fn.name },
        remediation:
          `-- if this should not be public:\n` +
          `REVOKE EXECUTE ON FUNCTION ${fqn} FROM ${exposedTo.join(", ")};\n` +
          `-- or re-check authorization inside the function body`,
        evidence: { owner: fn.owner, executeRoles: fn.executeRoles, hasSearchPath: fn.hasSearchPath },
      });
    }

    if (!fn.hasSearchPath) {
      const sev: Severity = exposedTo.length > 0 ? "high" : "medium";
      findings.push({
        id: findingId("rls-audit", "rpc.definer-search-path", scope),
        category: "rls-audit",
        ruleId: "rpc.definer-search-path",
        severity: sev,
        title: `SECURITY DEFINER function ${scope} has no pinned search_path`,
        description:
          `Function ${fqn} is SECURITY DEFINER but does not pin its search_path. ` +
          `A caller who can create objects in a schema on the path can shadow a function/operator the body calls and have it execute as ${fn.owner}. ` +
          `Pin the path so name resolution cannot be hijacked.`,
        location: { schema: fn.schema, table: fn.name },
        remediation: `ALTER FUNCTION ${fqn} SET search_path = '';\n-- then fully-qualify every object reference inside the function`,
        evidence: { owner: fn.owner, executeRoles: fn.executeRoles },
      });
    }
  }

  return findings;
}
