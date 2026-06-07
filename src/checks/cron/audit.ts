/**
 * pg_cron audit. Scheduled jobs run as the role that scheduled them, on a
 * timer, with no request context: auth.uid() is null and RLS that depends on
 * it is effectively bypassed. That is by design, which is exactly why it is
 * worth surfacing: a cron job is automated, privileged, and invisible to the
 * usual code-review surface.
 *
 * jimmy lists every scheduled job so a reviewer can confirm what runs
 * automatically and as whom, and flags the sharp edges:
 *   - jobs that call into untrusted surfaces (pg_net http) can exfiltrate.
 *   - jobs owned by a superuser doing DML on user tables bypass RLS silently.
 *
 * Read-only. No-op when pg_cron is not installed.
 */

import type pg from "pg";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

type Client = pg.PoolClient | pg.Client;

interface CronJobRow {
  jobid: number;
  schedule: string;
  command: string;
  username: string;
  active: boolean;
  jobname: string | null;
}

export interface CronAuditResult {
  findings: Finding[];
  cronPresent: boolean;
}

export async function auditCron(client: Client): Promise<CronAuditResult> {
  const present = await client.query(
    `SELECT 1 FROM pg_extension WHERE extname = 'pg_cron'`,
  );
  if ((present.rowCount ?? 0) === 0) {
    return { findings: [], cronPresent: false };
  }

  let jobs;
  try {
    jobs = await client.query<CronJobRow>(
      `SELECT jobid, schedule, command, username, active, jobname FROM cron.job ORDER BY jobid`,
    );
  } catch {
    // cron.job may not be readable by the connecting role.
    return { findings: [], cronPresent: true };
  }

  const findings: Finding[] = [];
  for (const j of jobs.rows) {
    if (!j.active) continue;
    const label = j.jobname ?? `job ${j.jobid}`;
    const cmd = j.command.toLowerCase();

    const callsNet = /\bnet\.http_|\bhttp_(get|post)\b|\bhttp\(/.test(cmd);
    const doesDml = /\b(insert|update|delete|truncate)\b/.test(cmd);
    const isPrivileged = ["postgres", "supabase_admin"].includes(j.username.toLowerCase());

    let severity: Severity = "info";
    const reasons: string[] = [];
    if (callsNet) {
      severity = "medium";
      reasons.push("calls out over pg_net/http (potential data exfiltration path)");
    }
    if (doesDml && isPrivileged) {
      severity = severity === "medium" ? "high" : "medium";
      reasons.push(`runs DML as the privileged role ${j.username}, bypassing RLS`);
    }

    findings.push({
      id: findingId("rls-audit", "cron.scheduled-job", String(j.jobid)),
      category: "rls-audit",
      ruleId: "cron.scheduled-job",
      severity,
      title: `Scheduled job ${label} runs as ${j.username} on "${j.schedule}"`,
      description:
        `pg_cron ${label} runs automatically as ${j.username} with no request context, so any RLS that depends on auth.uid() is bypassed. ` +
        (reasons.length > 0 ? `Sharp edges: ${reasons.join("; ")}. ` : "") +
        `Confirm this job is intended and that its privileges are the minimum required.`,
      location: { role: j.username },
      evidence: { jobid: j.jobid, schedule: j.schedule, command: j.command.slice(0, 300) },
    });
  }

  return { findings, cronPresent: true };
}
