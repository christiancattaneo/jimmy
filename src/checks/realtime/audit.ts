/**
 * Supabase realtime audit. Realtime broadcasts row changes to subscribed
 * clients via a Postgres logical-replication publication (by convention
 * `supabase_realtime`). A table added to that publication streams every
 * insert/update/delete to whoever is subscribed.
 *
 * The hazard: realtime only filters those broadcasts by RLS when RLS is
 * actually enabled and the policies are correct. A table in the publication
 * with RLS disabled (or a permissive policy) leaks every change to every
 * subscriber, which is a quieter and easier-to-miss leak than a REST endpoint
 * because nobody "called" anything.
 *
 * Read-only. Cross-references publication membership (live) with the RLS
 * posture already in the snapshot.
 */

import type pg from "pg";
import type { SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding } from "../../report/findings.js";

type Client = pg.PoolClient | pg.Client;

interface PublicationTableRow {
  schemaname: string;
  tablename: string;
  pubname: string;
}

export interface RealtimeAuditResult {
  findings: Finding[];
  /** True if a realtime-style publication exists. */
  realtimePresent: boolean;
}

const REALTIME_PUBLICATIONS = ["supabase_realtime"];

export async function auditRealtime(
  client: Client,
  snapshot: SchemaSnapshot,
): Promise<RealtimeAuditResult> {
  const pubs = await client.query<{ pubname: string }>(
    `SELECT pubname FROM pg_publication WHERE pubname = ANY($1::text[])`,
    [`{${REALTIME_PUBLICATIONS.join(",")}}`],
  );
  if ((pubs.rowCount ?? 0) === 0) {
    return { findings: [], realtimePresent: false };
  }

  const tables = await client.query<PublicationTableRow>(
    `SELECT schemaname, tablename, pubname FROM pg_publication_tables WHERE pubname = ANY($1::text[])`,
    [`{${REALTIME_PUBLICATIONS.join(",")}}`],
  );

  const findings: Finding[] = [];
  const rlsByTable = new Map<string, boolean>();
  for (const t of snapshot.tables) {
    rlsByTable.set(`${t.schema}.${t.name}`, t.rlsEnabled);
  }
  const hasPolicy = new Set(snapshot.policies.map((p) => `${p.schema}.${p.table}`));

  for (const t of tables.rows) {
    const fqn = `${t.schemaname}.${t.tablename}`;
    const rlsEnabled = rlsByTable.get(fqn);
    // Only reason about tables we introspected (public-facing). System tables
    // in the publication are not our concern.
    if (rlsEnabled === undefined) continue;

    if (!rlsEnabled) {
      findings.push({
        id: findingId("rls-audit", "realtime.broadcast-no-rls", fqn),
        category: "rls-audit",
        ruleId: "realtime.broadcast-no-rls",
        severity: "high",
        title: `${fqn} is broadcast by realtime but has RLS disabled`,
        description:
          `Table ${fqn} is in the ${t.pubname} publication, so every insert/update/delete is streamed to subscribed clients. ` +
          `RLS is disabled, so realtime applies no per-row filtering: any subscriber receives every change to every row. Enable and force RLS, or remove the table from the publication.`,
        location: { schema: t.schemaname, table: t.tablename },
        remediation:
          `ALTER TABLE ${fqn} ENABLE ROW LEVEL SECURITY;\n` +
          `-- or stop broadcasting it:\n` +
          `-- ALTER PUBLICATION ${t.pubname} DROP TABLE ${fqn};`,
        evidence: { publication: t.pubname },
      });
    } else if (!hasPolicy.has(fqn)) {
      findings.push({
        id: findingId("rls-audit", "realtime.broadcast-no-policy", fqn),
        category: "rls-audit",
        ruleId: "realtime.broadcast-no-policy",
        severity: "medium",
        title: `${fqn} is broadcast by realtime with RLS on but no policy`,
        description:
          `Table ${fqn} is in the ${t.pubname} publication with RLS enabled but no policy. Realtime delivery for non-privileged subscribers should be empty, ` +
          `which usually means either the table should not be broadcast or a SELECT policy is missing. Confirm which.`,
        location: { schema: t.schemaname, table: t.tablename },
        evidence: { publication: t.pubname },
      });
    }
  }

  return { findings, realtimePresent: true };
}
