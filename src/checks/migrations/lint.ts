/**
 * Migration linter. Squawk-style. Reads SQL files and flags dangerous DDL.
 *
 * The linter is intentionally simple. It runs a regex over each statement.
 * Static SQL parsing in TypeScript without a heavy dependency would be
 * brittle, and these patterns are precise enough for the common bad cases.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

export interface MigrationLintOptions {
  /** Lint a single file. */
  file?: string;
  /** Lint every .sql file in this directory tree. */
  dir?: string;
}

interface Rule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  test: (statement: string) => boolean;
  remediation?: (statement: string) => string;
}

function stripComments(sql: string): string {
  let out = "";
  let i = 0;
  let inLine = false;
  let inBlock = false;
  let inString: '"' | "'" | null = null;
  while (i < sql.length) {
    const c = sql[i]!;
    const n = i + 1 < sql.length ? sql[i + 1]! : "";
    if (inLine) {
      if (c === "\n") {
        inLine = false;
        out += c;
      }
      i++;
      continue;
    }
    if (inBlock) {
      if (c === "*" && n === "/") {
        inBlock = false;
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    if (inString) {
      out += c;
      if (c === inString) inString = null;
      i++;
      continue;
    }
    if (c === "-" && n === "-") {
      inLine = true;
      i += 2;
      continue;
    }
    if (c === "/" && n === "*") {
      inBlock = true;
      i += 2;
      continue;
    }
    if (c === "'" || c === '"') {
      inString = c;
      out += c;
      i++;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

interface SplitStatement {
  text: string;
  /** 1-indexed line number in the original (post-comment-strip) text. */
  line: number;
}

function splitStatementsWithPositions(sql: string): SplitStatement[] {
  const stripped = stripComments(sql);
  const parts: SplitStatement[] = [];
  let current = "";
  let currentStartLine = 1;
  let line = 1;
  let inString: '"' | "'" | null = null;
  let dollarTag: string | null = null;
  let inDollar = false;
  for (let i = 0; i < stripped.length; i++) {
    const c = stripped[i]!;
    if (current.trim().length === 0 && c !== "\n") {
      currentStartLine = line;
    }
    if (inDollar) {
      current += c;
      if (c === "\n") line++;
      const closing = `$${dollarTag}$`;
      if (c === "$" && stripped.startsWith(closing, i)) {
        current += closing.slice(1);
        i += closing.length - 1;
        inDollar = false;
        dollarTag = null;
      }
      continue;
    }
    if (inString) {
      current += c;
      if (c === "\n") line++;
      if (c === inString) inString = null;
      continue;
    }
    if (c === "$") {
      const m = stripped.slice(i).match(/^\$([a-zA-Z_]*)\$/);
      if (m) {
        dollarTag = m[1] ?? "";
        inDollar = true;
        current += m[0];
        i += m[0].length - 1;
        continue;
      }
    }
    if (c === "'" || c === '"') {
      inString = c;
      current += c;
      continue;
    }
    if (c === ";") {
      const trimmed = current.trim();
      if (trimmed.length > 0) parts.push({ text: trimmed, line: currentStartLine });
      current = "";
      continue;
    }
    current += c;
    if (c === "\n") line++;
  }
  const lastTrim = current.trim();
  if (lastTrim.length > 0) parts.push({ text: lastTrim, line: currentStartLine });
  return parts;
}

function splitStatements(sql: string): string[] {
  return splitStatementsWithPositions(sql).map((p) => p.text);
}

const RULES: Rule[] = [
  {
    id: "migration.add-not-null-without-default",
    severity: "high",
    title: "ADD COLUMN ... NOT NULL without DEFAULT",
    description:
      "Adding a NOT NULL column without a default rewrites the whole table on Postgres < 11 and fails on tables with existing rows. Use a default or backfill in two steps.",
    test: (s) => /alter\s+table\s+[^;]*add\s+column[^;]*not\s+null/i.test(s) && !/default/i.test(s),
  },
  {
    id: "migration.non-concurrent-index",
    severity: "high",
    title: "CREATE INDEX without CONCURRENTLY",
    description:
      "CREATE INDEX takes an ACCESS EXCLUSIVE on writers. On a busy table this stalls every write until the build finishes. Use CREATE INDEX CONCURRENTLY (and split it into its own migration; CONCURRENTLY cannot run inside a transaction).",
    test: (s) => /create\s+(unique\s+)?index/i.test(s) && !/concurrently/i.test(s) && !/temp(orary)?/i.test(s),
  },
  {
    id: "migration.type-rewrite",
    severity: "high",
    title: "ALTER COLUMN TYPE that may rewrite the table",
    description:
      "Changing a column's type usually rewrites every row. For long-running services, use a shadow column + backfill + swap.",
    test: (s) => /alter\s+table\s+[^;]*alter\s+column\s+[^;]*type\s+/i.test(s),
  },
  {
    id: "migration.add-fk-without-not-valid",
    severity: "medium",
    title: "ADD FOREIGN KEY without NOT VALID",
    description:
      "Adding a foreign key validates every existing row under a SHARE ROW EXCLUSIVE lock, blocking writes to both tables for the duration. Add the constraint NOT VALID, then VALIDATE CONSTRAINT in a separate statement (validation takes a weaker lock).",
    test: (s) =>
      /alter\s+table\s+[^;]*add\s+(constraint\s+\S+\s+)?foreign\s+key/i.test(s) &&
      !/not\s+valid/i.test(s),
  },
  {
    id: "migration.add-check-without-not-valid",
    severity: "medium",
    title: "ADD CHECK constraint without NOT VALID",
    description:
      "Adding a CHECK constraint scans the whole table to validate under an ACCESS EXCLUSIVE lock. Add it NOT VALID, then VALIDATE CONSTRAINT separately.",
    test: (s) =>
      /alter\s+table\s+[^;]*add\s+(constraint\s+\S+\s+)?check\s*\(/i.test(s) &&
      !/not\s+valid/i.test(s),
  },
  {
    id: "migration.add-unique-constraint",
    severity: "high",
    title: "ADD UNIQUE constraint (builds an index under an exclusive lock)",
    description:
      "ALTER TABLE ... ADD CONSTRAINT ... UNIQUE builds the backing index while holding ACCESS EXCLUSIVE. Build a unique index CONCURRENTLY first, then ADD CONSTRAINT ... USING INDEX.",
    test: (s) =>
      /alter\s+table\s+[^;]*add\s+(constraint\s+\S+\s+)?unique\s*\(/i.test(s) &&
      !/using\s+index/i.test(s),
  },
  {
    id: "migration.volatile-default",
    severity: "medium",
    title: "ADD COLUMN with a volatile DEFAULT",
    description:
      "Adding a column whose default is a volatile function (random(), gen_random_uuid(), clock_timestamp()) forces a full table rewrite to materialize a distinct value per row, unlike a constant default which is metadata-only on modern Postgres. Backfill in batches instead.",
    test: (s) =>
      /alter\s+table\s+[^;]*add\s+column[^;]*default\s+[^;]*(random\s*\(|gen_random_uuid\s*\(|uuid_generate_v\d\s*\(|clock_timestamp\s*\()/i.test(s),
  },
  {
    id: "migration.partitioned-index",
    severity: "medium",
    title: "CREATE INDEX on a partitioned table",
    description:
      "Creating an index on a partitioned table is not supported with CONCURRENTLY. Create the index on each partition CONCURRENTLY, then attach, or create it ONLY on the parent and build children separately to avoid a long lock.",
    test: (s) => /create\s+(unique\s+)?index\s+concurrently[^;]*\bon\s+only\b/i.test(s),
  },
  {
    id: "migration.drop-column",
    severity: "medium",
    title: "DROP COLUMN",
    description:
      "Dropping a column breaks any code that still references it. Even if you have updated all callers, an in-flight deploy may still be running the old code.",
    test: (s) => /alter\s+table\s+[^;]*drop\s+column/i.test(s),
  },
  {
    id: "migration.drop-table",
    severity: "high",
    title: "DROP TABLE",
    description:
      "Dropping a table is destructive. Verify nothing reads from it (including replicas, queues, and external tooling) before merging.",
    test: (s) => /^drop\s+table\b/i.test(s),
  },
  {
    id: "migration.rename-column",
    severity: "medium",
    title: "RENAME COLUMN",
    description:
      "Renames are not backwards compatible. Either deploy the rename in two phases (add new column, dual-write, switch reads, drop old) or expect old code to crash mid-deploy.",
    test: (s) => /alter\s+table\s+[^;]*rename\s+column/i.test(s),
  },
  {
    id: "migration.rename-table",
    severity: "medium",
    title: "RENAME TABLE",
    description:
      "Renaming a table requires every dependent (views, functions, application code, ORMs) to know about the rename simultaneously. Add a view at the old name during transition.",
    test: (s) => /alter\s+table\s+[^;]*rename\s+to\b/i.test(s),
  },
  {
    id: "migration.disable-rls",
    severity: "critical",
    title: "DISABLE ROW LEVEL SECURITY",
    description:
      "ALTER TABLE ... DISABLE ROW LEVEL SECURITY removes tenant isolation. If this is intentional, document it; otherwise this is a backdoor.",
    test: (s) => /disable\s+row\s+level\s+security/i.test(s),
  },
  {
    id: "migration.truncate",
    severity: "high",
    title: "TRUNCATE",
    description:
      "TRUNCATE bypasses triggers (unless explicitly cascaded) and audit logs that depend on row-level events. Confirm intent.",
    test: (s) => /^truncate\b/i.test(s),
  },
  {
    id: "migration.set-not-null-on-existing",
    severity: "medium",
    title: "ALTER COLUMN SET NOT NULL on existing column",
    description:
      "SET NOT NULL scans the entire table to validate. On large tables this is a long lock. Use NOT VALID + VALIDATE in two steps when possible.",
    test: (s) => /alter\s+table\s+[^;]*alter\s+column\s+[^;]*set\s+not\s+null/i.test(s),
  },
];

const DDL_RE = /^(alter\s+table|create\s+(unique\s+)?index|drop\s+|truncate\b)/i;
const LOCK_TIMEOUT_RE = /set\s+lock_timeout/i;

/**
 * Inline suppression. A comment of the form:
 *   -- jimmy:ignore                 (suppress every rule on the next statement)
 *   -- jimmy:ignore migration.drop-table   (suppress one rule)
 *   -- jimmy:ignore-file            (suppress the whole file)
 * The directive applies to the next statement (skipping blank/comment lines)
 * or, when trailing, to the statement on its own line.
 */
interface IgnoreDirective {
  line: number;
  /** Specific rule id, or null for "all rules". */
  rule: string | null;
  file: boolean;
}

const IGNORE_RE = /--\s*jimmy:ignore(-file)?(?:\s+(\S+))?/i;

function parseIgnoreDirectives(text: string): IgnoreDirective[] {
  const out: IgnoreDirective[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(IGNORE_RE);
    if (m) {
      out.push({ line: i + 1, file: m[1] === "-file", rule: m[2] ?? null });
    }
  }
  return out;
}

function isCommentOrBlank(line: string): boolean {
  const t = line.trim();
  return t === "" || t.startsWith("--");
}

/**
 * Does a directive suppress a finding at `findingLine` for `ruleId`?
 * A directive on line D applies if D === findingLine (trailing/same line) or if
 * D is immediately above the finding, separated only by comment/blank lines.
 */
function isSuppressed(
  finding: Finding,
  directives: IgnoreDirective[],
  lines: string[],
): boolean {
  if (directives.some((d) => d.file)) return true;
  const findingLine = finding.location.line ?? 0;
  if (findingLine === 0) return false;
  for (const d of directives) {
    if (d.rule !== null && d.rule !== finding.ruleId) continue;
    if (d.line === findingLine) return true;
    if (d.line < findingLine) {
      // walk from the line just above the finding up to the directive; all
      // intervening lines must be comments/blank for the directive to attach.
      let allComments = true;
      for (let ln = findingLine - 1; ln > d.line; ln--) {
        if (!isCommentOrBlank(lines[ln - 1] ?? "")) {
          allComments = false;
          break;
        }
      }
      if (allComments) return true;
    }
  }
  return false;
}

export function lintSqlText(text: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const statements = splitStatementsWithPositions(text);
  const directives = parseIgnoreDirectives(text);
  const rawLines = text.split("\n");

  let hasDdl = false;
  let setsLockTimeout = false;
  let firstDdlLine = 1;

  for (let i = 0; i < statements.length; i++) {
    const { text: stmt, line } = statements[i]!;
    if (DDL_RE.test(stmt) && !/temp(orary)?/i.test(stmt)) {
      if (!hasDdl) firstDdlLine = line;
      hasDdl = true;
    }
    if (LOCK_TIMEOUT_RE.test(stmt)) setsLockTimeout = true;
    for (const rule of RULES) {
      if (rule.test(stmt)) {
        const scope = `${filePath}:${rule.id}:${i}`;
        findings.push({
          id: findingId("migrations", rule.id, scope),
          category: "migrations",
          ruleId: rule.id,
          severity: rule.severity,
          title: `${rule.title} (${basename(filePath)})`,
          description: rule.description,
          location: { file: filePath, line },
          evidence: { statement: stmt.slice(0, 400) },
          remediation: rule.remediation ? rule.remediation(stmt) : undefined,
        });
      }
    }
  }

  // lock_timeout is a session setting: one SET covers the whole migration.
  // Fire at most once per file when DDL exists but no statement sets it.
  if (hasDdl && !setsLockTimeout) {
    findings.push({
      id: findingId("migrations", "migration.lock-timeout-missing", filePath),
      category: "migrations",
      ruleId: "migration.lock-timeout-missing",
      severity: "low",
      title: `Migration runs DDL without setting lock_timeout (${basename(filePath)})`,
      description:
        "This migration runs DDL but never sets lock_timeout. Without it, a single long-running query can make the migration block all access and turn into an outage. Add `SET lock_timeout = '5s';` at the top.",
      location: { file: filePath, line: firstDdlLine },
      remediation: "SET lock_timeout = '5s';",
    });
  }

  if (directives.length === 0) return findings;
  return findings.filter((f) => !isSuppressed(f, directives, rawLines));
}

export function lintFile(filePath: string): Finding[] {
  const text = readFileSync(filePath, "utf-8");
  return lintSqlText(text, filePath);
}

export function lintDirectory(dirPath: string): Finding[] {
  const files: string[] = [];
  walk(dirPath, files);
  const all: Finding[] = [];
  for (const f of files) {
    if (!f.endsWith(".sql")) continue;
    all.push(...lintFile(f));
  }
  return all;
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(full, out);
    } else if (st.isFile()) {
      out.push(full);
    }
  }
}

export const _internal = { stripComments, splitStatements, RULES };
