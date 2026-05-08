#!/usr/bin/env node

/**
 * jimmy CLI. Read-only by default. Refuses to run on databases whose name
 * looks like production.
 */

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { writeFileSync } from "node:fs";

import { connect } from "../db/connect.js";
import { introspect } from "../db/introspect.js";
import { SafetyGuard, SafetyViolationError, DEFAULT_SAFETY_CONFIG, type SafetyMode } from "../safety/index.js";
import { auditRls } from "../checks/rls/audit.js";
import { fuzzRls } from "../checks/rls/fuzz.js";
import { auditSchema } from "../checks/schema/audit.js";
import { lintFile, lintDirectory } from "../checks/migrations/lint.js";
import { runAnomalyProbes, ALL_ISOLATION_LEVELS, type AnomalyName, type IsolationLevel } from "../checks/anomalies/probes.js";
import { detectNplusOne, pgStatStatementsAvailable, readPgStatStatements, readQueryLog } from "../checks/nplusone/detect.js";
import { buildReport, reportToJson, reportToMarkdown } from "../report/generate.js";
import { isAtOrAbove, type Finding, type Severity } from "../report/findings.js";

const program = new Command();

function log(verbose: boolean) {
  return {
    debug: (m: string) => verbose && console.log(chalk.gray(`[debug] ${m}`)),
    info: (m: string) => console.log(chalk.cyan(`[info] ${m}`)),
    warn: (m: string) => console.log(chalk.yellow(`[warn] ${m}`)),
    error: (m: string) => console.log(chalk.red(`[error] ${m}`)),
    ok: (m: string) => console.log(chalk.green(`[ok] ${m}`)),
  };
}

function printBanner(): void {
  console.log(chalk.bold("\n  jimmy"));
  console.log(chalk.gray("  pries open the database the application thinks is locked\n"));
}

interface CommonOpts {
  db?: string;
  output?: string;
  verbose?: boolean;
  failOn?: Severity;
  iKnowWhatImDoing?: boolean;
  allowHost?: string[];
  mode?: SafetyMode;
}

function buildGuard(opts: CommonOpts): SafetyGuard {
  return new SafetyGuard({
    ...DEFAULT_SAFETY_CONFIG,
    override: opts.iKnowWhatImDoing ?? false,
    allowedHosts: opts.allowHost ?? [],
    mode: opts.mode ?? "read-only",
  });
}

async function buildConnection(opts: CommonOpts) {
  if (!opts.db) {
    throw new Error("--db is required (postgres connection string)");
  }
  const guard = buildGuard(opts);
  return connect({ connectionString: opts.db, guard });
}

function saveReport(findings: Finding[], output: string, target: string, title: string): { md: string; json: string } {
  const report = buildReport(findings, { title, target });
  const md = `${output}.md`;
  const json = `${output}.json`;
  writeFileSync(md, reportToMarkdown(report));
  writeFileSync(json, reportToJson(report));
  return { md, json };
}

function printSummary(findings: Finding[]): void {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity]++;
  console.log(chalk.bold("\n  results"));
  console.log(`  total: ${findings.length}`);
  console.log(`  critical: ${chalk.red(counts.critical)}`);
  console.log(`  high:     ${chalk.redBright(counts.high)}`);
  console.log(`  medium:   ${chalk.yellow(counts.medium)}`);
  console.log(`  low:      ${chalk.green(counts.low)}`);
  console.log(`  info:     ${chalk.gray(counts.info)}\n`);
}

function exitForFindings(findings: Finding[], failOn: Severity): void {
  for (const f of findings) {
    if (isAtOrAbove(f.severity, failOn)) process.exit(2);
  }
}

async function rlsAuditCmd(opts: CommonOpts) {
  printBanner();
  const l = log(opts.verbose ?? false);
  const sp = ora("introspecting schema").start();
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "read-only" });
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.succeed(`introspected ${snapshot.tables.length} tables, ${snapshot.policies.length} policies`);
    const findings = auditRls(snapshot);
    const out = opts.output ?? "jimmy-rls";
    const paths = saveReport(findings, out, conn.shape.database, "jimmy: rls audit");
    l.ok(`wrote ${paths.md} and ${paths.json}`);
    printSummary(findings);
    exitForFindings(findings, opts.failOn ?? "high");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function rlsFuzzCmd(opts: CommonOpts & { roles?: string; maxTables?: number }) {
  printBanner();
  const l = log(opts.verbose ?? false);
  const sp = ora("introspecting").start();
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "test-schema" });
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.text = "fuzzing rls (creates throwaway rows inside a rolled-back transaction)";
    const result = await fuzzRls(conn, snapshot, {
      roles: opts.roles?.split(",").map((s) => s.trim()).filter(Boolean),
      maxTables: opts.maxTables,
    });
    sp.succeed(`fuzzed ${result.history.length} probes, skipped ${result.skipped.length} tables`);
    const out = opts.output ?? "jimmy-rls-fuzz";
    const paths = saveReport(result.findings, out, conn.shape.database, "jimmy: rls fuzz");
    l.ok(`wrote ${paths.md} and ${paths.json}`);
    if (result.skipped.length > 0) {
      l.warn(`skipped ${result.skipped.length} tables (see report)`);
    }
    printSummary(result.findings);
    exitForFindings(result.findings, opts.failOn ?? "high");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function schemaCmd(opts: CommonOpts) {
  printBanner();
  const l = log(opts.verbose ?? false);
  const sp = ora("auditing schema").start();
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "read-only" });
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.succeed(`audited ${snapshot.tables.length} tables`);
    const findings = auditSchema(snapshot);
    const out = opts.output ?? "jimmy-schema";
    const paths = saveReport(findings, out, conn.shape.database, "jimmy: schema integrity");
    l.ok(`wrote ${paths.md} and ${paths.json}`);
    printSummary(findings);
    exitForFindings(findings, opts.failOn ?? "high");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function migrationsCmd(opts: { file?: string; dir?: string; output?: string; failOn?: Severity }) {
  printBanner();
  if (!opts.file && !opts.dir) {
    console.log(chalk.red("[error] --file or --dir required"));
    process.exit(1);
  }
  const findings: Finding[] = [];
  const sp = ora("linting migrations").start();
  try {
    if (opts.file) findings.push(...lintFile(opts.file));
    if (opts.dir) findings.push(...lintDirectory(opts.dir));
    sp.succeed(`linted ${opts.file ? "1 file" : "directory " + opts.dir}`);
    const out = opts.output ?? "jimmy-migrations";
    const paths = saveReport(findings, out, opts.file ?? opts.dir ?? ".", "jimmy: migration lint");
    console.log(chalk.green(`[ok] wrote ${paths.md} and ${paths.json}`));
    printSummary(findings);
    exitForFindings(findings, opts.failOn ?? "high");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  }
}

async function anomaliesCmd(opts: CommonOpts & { tests?: string; levels?: string }) {
  printBanner();
  const l = log(opts.verbose ?? false);
  const sp = ora("running anomaly probes").start();
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "test-schema" });
    const tests = opts.tests
      ? (opts.tests.split(",").map((s) => s.trim()) as AnomalyName[])
      : undefined;
    const levels = opts.levels
      ? (opts.levels.split(",").map((s) => s.trim().toUpperCase()) as IsolationLevel[])
      : ALL_ISOLATION_LEVELS;
    const result = await runAnomalyProbes(conn, { anomalies: tests, isolationLevels: levels });
    sp.succeed(`ran ${result.results.length} probes`);
    const out = opts.output ?? "jimmy-anomalies";
    const paths = saveReport(result.findings, out, conn.shape.database, "jimmy: transaction anomalies");
    l.ok(`wrote ${paths.md} and ${paths.json}`);
    for (const r of result.results) {
      const tag = r.observable ? chalk.red("OBSERVABLE") : chalk.green("safe");
      console.log(`  ${tag} ${r.anomaly} @ ${r.level}  ${chalk.gray(r.detail)}`);
    }
    printSummary(result.findings);
    exitForFindings(result.findings, opts.failOn ?? "high");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function nplusoneCmd(opts: CommonOpts & { threshold?: number; log?: string }) {
  printBanner();
  const l = log(opts.verbose ?? false);
  const sp = ora("collecting query stats").start();
  try {
    let stats;
    if (opts.log) {
      stats = readQueryLog(opts.log);
      sp.succeed(`read ${stats.length} unique templates from log`);
    } else {
      const conn = await buildConnection({ ...opts, mode: "read-only" });
      try {
        const has = await pgStatStatementsAvailable(conn);
        if (!has) {
          sp.warn("pg_stat_statements is not installed; pass --log <file> instead");
          return;
        }
        stats = await readPgStatStatements(conn);
        sp.succeed(`read ${stats.length} templates from pg_stat_statements`);
      } finally {
        await conn.end();
      }
    }
    const findings = detectNplusOne(stats, { threshold: opts.threshold ?? 50 });
    const out = opts.output ?? "jimmy-nplusone";
    const paths = saveReport(findings, out, opts.db ?? opts.log ?? ".", "jimmy: n+1 detection");
    l.ok(`wrote ${paths.md} and ${paths.json}`);
    printSummary(findings);
    exitForFindings(findings, opts.failOn ?? "high");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  }
}

async function scanCmd(opts: CommonOpts & { migrationsDir?: string }) {
  printBanner();
  const l = log(opts.verbose ?? false);
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "read-only" });
    const sp = ora("introspecting").start();
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.succeed(`introspected ${snapshot.tables.length} tables`);

    const findings: Finding[] = [];

    const sp2 = ora("auditing rls").start();
    findings.push(...auditRls(snapshot));
    sp2.succeed("rls audit done");

    const sp3 = ora("auditing schema integrity").start();
    findings.push(...auditSchema(snapshot));
    sp3.succeed("schema audit done");

    if (opts.migrationsDir) {
      const sp4 = ora("linting migrations").start();
      findings.push(...lintDirectory(opts.migrationsDir));
      sp4.succeed("migration lint done");
    }

    const out = opts.output ?? "jimmy-report";
    const paths = saveReport(findings, out, conn.shape.database, "jimmy: full scan");
    l.ok(`wrote ${paths.md} and ${paths.json}`);
    printSummary(findings);
    exitForFindings(findings, opts.failOn ?? "high");
  } catch (e) {
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

function coerceMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function handleError(e: unknown): never {
  if (e instanceof SafetyViolationError) {
    console.log(chalk.red(`[safety] ${e.violation}: ${e.message}`));
    process.exit(3);
  }
  console.log(chalk.red(`[error] ${coerceMsg(e)}`));
  process.exit(4);
}

program.name("jimmy").description("pries open the database the application thinks is locked").version("0.1.0");

const dbOpt = (cmd: Command) =>
  cmd
    .option("-d, --db <url>", "postgres connection string")
    .option("-o, --output <file>", "output report basename (without extension)")
    .option("-v, --verbose", "verbose logging")
    .option("--fail-on <severity>", "exit nonzero if findings at or above this severity", "high")
    .option("--allow-host <host>", "host allowlist (repeat for multiple)", (v: string, p: string[] = []) => [...p, v], [])
    .option("--i-know-what-im-doing", "override safety guards (do not use)", false);

const rls = program.command("rls").description("row-level security checks");
dbOpt(rls.command("audit").description("static rls audit, read-only").action(rlsAuditCmd));
dbOpt(
  rls
    .command("fuzz")
    .description("rls property test: seed two tenants, prove A cannot touch B")
    .option("--roles <roles>", "comma-separated roles to impersonate", "authenticated,anon")
    .option("--max-tables <n>", "limit number of tables to probe", (v: string) => parseInt(v, 10))
    .action(rlsFuzzCmd),
);

dbOpt(program.command("schema").description("schema integrity audit").action(schemaCmd));

const mig = program.command("migrations").description("migration safety");
mig
  .command("lint")
  .description("squawk-style sql migration linter")
  .option("--file <file>", "single sql file")
  .option("--dir <dir>", "directory of sql files (recursive)")
  .option("-o, --output <file>", "output report basename")
  .option("--fail-on <severity>", "fail-on severity", "high")
  .action(migrationsCmd);

dbOpt(
  program
    .command("anomalies")
    .description("hermitage-style transaction anomaly probes")
    .option("--tests <names>", "comma-separated subset: lost-update,write-skew,read-skew,g2-item")
    .option("--levels <levels>", "comma-separated isolation levels")
    .action(anomaliesCmd),
);

dbOpt(
  program
    .command("nplusone")
    .description("n+1 query detection")
    .option("--threshold <n>", "execution count threshold", (v: string) => parseInt(v, 10), 50)
    .option("--log <file>", "read from a query log instead of pg_stat_statements")
    .action(nplusoneCmd),
);

dbOpt(
  program
    .command("scan")
    .description("read-only scan: rls audit + schema integrity (+ migrations if --migrations-dir)")
    .option("--migrations-dir <dir>", "include migrations linting")
    .action(scanCmd),
);

process.on("unhandledRejection", (reason) => {
  if (reason instanceof SafetyViolationError) {
    console.log(chalk.red(`[safety] ${reason.violation}: ${reason.message}`));
    process.exit(3);
  }
  console.log(chalk.red(`[error] ${reason instanceof Error ? reason.message : String(reason)}`));
  process.exit(4);
});

program.parse();
