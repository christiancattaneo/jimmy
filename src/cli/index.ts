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
import { auditRpc } from "../checks/rls/rpc.js";
import { auditStorage } from "../checks/storage/audit.js";
import { auditRealtime } from "../checks/realtime/audit.js";
import { auditCron } from "../checks/cron/audit.js";
import { fuzzRls } from "../checks/rls/fuzz.js";
import { auditSchema } from "../checks/schema/audit.js";
import { auditPii } from "../checks/pii/audit.js";
import { lintFile, lintDirectory } from "../checks/migrations/lint.js";
import { runAnomalyProbes, ALL_ISOLATION_LEVELS, type AnomalyName, type IsolationLevel } from "../checks/anomalies/probes.js";
import { detectNplusOne, pgStatStatementsAvailable, readPgStatStatements, readQueryLog } from "../checks/nplusone/detect.js";
import { buildReport, reportToJson, reportToMarkdown, reportToSarif } from "../report/generate.js";
import { anyFails, parseFailOn, type Finding, type Severity } from "../report/findings.js";
import { applyBaseline, readBaseline, writeBaseline } from "../report/baseline.js";
import { explainRule, listRules } from "../report/catalog.js";
import { loadConfig, applyDisabledRules, type JimmyConfig } from "../config.js";
import { existsSync } from "node:fs";

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

function printBanner(quiet?: boolean): void {
  if (quiet) return;
  console.log(chalk.bold("\n  jimmy"));
  console.log(chalk.gray("  pries open the database the application thinks is locked\n"));
}

interface CommonOpts {
  db?: string;
  output?: string;
  verbose?: boolean;
  failOn?: string;
  iKnowWhatImDoing?: boolean;
  allowHost?: string[];
  mode?: SafetyMode;
  baseline?: string;
  updateBaseline?: boolean;
  quiet?: boolean;
  config?: string;
}

/** Load config once per command and cache it on the opts object. */
function configFor(opts: CommonOpts): JimmyConfig {
  return loadConfig(opts.config);
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

function saveReport(findings: Finding[], output: string, target: string, title: string): { md: string; json: string; sarif: string } {
  const report = buildReport(findings, { title, target });
  const md = `${output}.md`;
  const json = `${output}.json`;
  const sarif = `${output}.sarif`;
  writeFileSync(md, reportToMarkdown(report));
  writeFileSync(json, reportToJson(report));
  writeFileSync(sarif, reportToSarif(report));
  return { md, json, sarif };
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

/**
 * Shared end-of-command handling: optional baseline write/apply, report save,
 * summary print, and exit code. Centralizes the logic every command shares.
 */
function finalize(
  findings: Finding[],
  opts: CommonOpts & { baseline?: string; updateBaseline?: boolean },
  defaultOut: string,
  title: string,
  target: string,
): void {
  const l = log(opts.verbose ?? false);
  const config = configFor(opts);

  // config-level rule disabling applies before everything else.
  findings = applyDisabledRules(findings, config.disabledRules);

  const baselinePath = opts.baseline ?? config.baseline;

  if (opts.updateBaseline) {
    const path = baselinePath ?? ".jimmy-baseline.json";
    writeBaseline(path, findings);
    l.ok(`wrote baseline with ${new Set(findings.map((f) => f.id)).size} accepted findings to ${path}`);
  }

  let effective = findings;
  let baselinedCount = 0;
  let resolvedCount = 0;
  if (baselinePath && !opts.updateBaseline && existsSync(baselinePath)) {
    const applied = applyBaseline(findings, readBaseline(baselinePath));
    effective = applied.newFindings;
    baselinedCount = applied.baselined.length;
    resolvedCount = applied.resolvedIds.length;
  }

  const out = opts.output ?? defaultOut;
  const paths = saveReport(findings, out, target, title);
  // CLI --fail-on wins over config.failOn wins over the built-in "high".
  const failOnSpec = opts.failOn ?? config.failOn ?? "high";
  const spec = parseFailOn(String(failOnSpec));
  const fails = anyFails(effective, spec);

  if (opts.quiet) {
    // One machine-friendly line, then the exit code does the talking.
    const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of effective) counts[f.severity]++;
    console.log(
      `jimmy: ${effective.length} findings (critical=${counts.critical} high=${counts.high} medium=${counts.medium} low=${counts.low}) -> ${paths.json}`,
    );
    if (fails) process.exit(2);
    return;
  }

  l.ok(`wrote ${paths.md} and ${paths.json}`);
  if (baselinedCount > 0) l.info(`${baselinedCount} findings suppressed by baseline`);
  if (resolvedCount > 0) l.info(`${resolvedCount} baselined findings are now resolved (consider --update-baseline)`);

  printSummary(findings);
  if (baselinedCount > 0) {
    console.log(`  new (after baseline): ${effective.length}\n`);
  }

  if (fails) process.exit(2);
}

async function rlsAuditCmd(opts: CommonOpts) {
  printBanner(opts.quiet);
  const l = log(opts.verbose ?? false);
  const sp = ora("introspecting schema").start();
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "read-only" });
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.succeed(`introspected ${snapshot.tables.length} tables, ${snapshot.policies.length} policies`);
    const cfg = configFor(opts);
    const findings = [
      ...auditRls(snapshot, { tenantColumnNames: cfg.tenantColumns, publicRoles: cfg.publicRoles }),
      ...auditRpc(snapshot, { publicRoles: cfg.publicRoles }),
    ];
    await conn.withClient(async (c) => {
      findings.push(...(await auditStorage(c)).findings);
      findings.push(...(await auditRealtime(c, snapshot)).findings);
      findings.push(...(await auditCron(c)).findings);
    });
    finalize(findings, opts, "jimmy-rls", "jimmy: rls audit", conn.shape.database);
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function rlsFuzzCmd(opts: CommonOpts & { roles?: string; maxTables?: number }) {
  printBanner(opts.quiet);
  const l = log(opts.verbose ?? false);
  const sp = ora("introspecting").start();
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "test-schema" });
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.text = "fuzzing rls (creates throwaway rows inside a rolled-back transaction)";
    const cfg = configFor(opts);
    const cliRoles = opts.roles?.split(",").map((s) => s.trim()).filter(Boolean);
    const result = await fuzzRls(conn, snapshot, {
      roles: cliRoles ?? cfg.roles,
      tenantColumnNames: cfg.tenantColumns,
      jwtSubKey: cfg.jwtSubKey,
      maxTables: opts.maxTables,
    });
    sp.succeed(`fuzzed ${result.history.length} probes, skipped ${result.skipped.length} tables`);
    if (result.skipped.length > 0) {
      l.warn(`skipped ${result.skipped.length} tables (see report info findings)`);
    }
    finalize(result.findings, opts, "jimmy-rls-fuzz", "jimmy: rls fuzz", conn.shape.database);
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function schemaCmd(opts: CommonOpts) {
  printBanner(opts.quiet);
  const l = log(opts.verbose ?? false);
  const sp = ora("auditing schema").start();
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "read-only" });
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.succeed(`audited ${snapshot.tables.length} tables`);
    const findings = [...auditSchema(snapshot), ...auditPii(snapshot)];
    finalize(findings, opts, "jimmy-schema", "jimmy: schema integrity", conn.shape.database);
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function migrationsCmd(
  opts: CommonOpts & { file?: string; dir?: string },
) {
  printBanner(opts.quiet);
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
    finalize(findings, opts, "jimmy-migrations", "jimmy: migration lint", opts.file ?? opts.dir ?? ".");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  }
}

async function anomaliesCmd(opts: CommonOpts & { tests?: string; levels?: string }) {
  printBanner(opts.quiet);
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
    for (const r of result.results) {
      const tag = r.observable ? chalk.red("OBSERVABLE") : chalk.green("safe");
      console.log(`  ${tag} ${r.anomaly} @ ${r.level}  ${chalk.gray(r.detail)}`);
    }
    const rec = result.recommendedLevel;
    console.log(
      rec
        ? `\n  recommended minimum isolation level for this workload: ${chalk.cyan(rec)}`
        : `\n  ${chalk.red("no isolation level was fully safe for the probed anomalies (unexpected)")}`,
    );
    finalize(result.findings, opts, "jimmy-anomalies", "jimmy: transaction anomalies", conn.shape.database);
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  } finally {
    if (conn) await conn.end();
  }
}

async function nplusoneCmd(opts: CommonOpts & { threshold?: number; log?: string }) {
  printBanner(opts.quiet);
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
    finalize(findings, opts, "jimmy-nplusone", "jimmy: n+1 detection", opts.db ?? opts.log ?? ".");
  } catch (e) {
    sp.fail(coerceMsg(e));
    handleError(e);
  }
}

async function scanCmd(opts: CommonOpts & { migrationsDir?: string }) {
  printBanner(opts.quiet);
  const l = log(opts.verbose ?? false);
  let conn: Awaited<ReturnType<typeof buildConnection>> | null = null;
  try {
    conn = await buildConnection({ ...opts, mode: "read-only" });
    const sp = ora("introspecting").start();
    const snapshot = await conn.withClient((c) => introspect(c));
    sp.succeed(`introspected ${snapshot.tables.length} tables`);

    const findings: Finding[] = [];

    const cfg = configFor(opts);
    const sp2 = ora("auditing rls").start();
    findings.push(...auditRls(snapshot, { tenantColumnNames: cfg.tenantColumns, publicRoles: cfg.publicRoles }));
    findings.push(...auditRpc(snapshot, { publicRoles: cfg.publicRoles }));
    let extras = "";
    await conn.withClient(async (c) => {
      const storage = await auditStorage(c);
      findings.push(...storage.findings);
      const realtime = await auditRealtime(c, snapshot);
      findings.push(...realtime.findings);
      const cron = await auditCron(c);
      findings.push(...cron.findings);
      const present = [
        storage.storagePresent && "storage",
        realtime.realtimePresent && "realtime",
        cron.cronPresent && "cron",
      ].filter(Boolean);
      if (present.length > 0) extras = ` (incl. ${present.join(", ")})`;
    });
    sp2.succeed(`rls audit done${extras}`);

    const sp3 = ora("auditing schema integrity").start();
    findings.push(...auditSchema(snapshot));
    findings.push(...auditPii(snapshot));
    sp3.succeed("schema audit done");

    if (opts.migrationsDir) {
      const sp4 = ora("linting migrations").start();
      findings.push(...lintDirectory(opts.migrationsDir));
      sp4.succeed("migration lint done");
    }

    finalize(findings, opts, "jimmy-report", "jimmy: full scan", conn.shape.database);
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
    .option(
      "--fail-on <spec>",
      "fail threshold. a severity (high) or per-category (default=high,rls=medium,schema=low). default: high",
    )
    .option("--config <file>", "path to jimmy.config.json (auto-discovered otherwise)")
    .option("--baseline <file>", "suppress findings present in this baseline file")
    .option("--update-baseline", "write the current findings as the new baseline", false)
    .option("--quiet", "minimal output for CI (one summary line, exit code)", false)
    .option("--allow-host <host>", "host allowlist (repeat for multiple)", (v: string, p: string[] = []) => [...p, v], [])
    .option("--i-know-what-im-doing", "override safety guards (do not use)", false);

const rls = program.command("rls").description("row-level security checks");
dbOpt(rls.command("audit").description("static rls audit, read-only").action(rlsAuditCmd));
dbOpt(
  rls
    .command("fuzz")
    .description("rls property test: seed two tenants, prove A cannot touch B")
    .option("--roles <roles>", "comma-separated roles to impersonate (default: authenticated,anon)")
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
  .option("--fail-on <spec>", "fail threshold: severity or per-category (default: high)")
  .option("--config <file>", "path to jimmy.config.json (auto-discovered otherwise)")
  .option("--baseline <file>", "suppress findings present in this baseline file")
  .option("--update-baseline", "write the current findings as the new baseline", false)
  .option("--quiet", "minimal output for CI (one summary line, exit code)", false)
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

program
  .command("explain")
  .description("explain a rule by id, or list all rules with --list")
  .argument("[ruleId]", "the rule id, e.g. rls.permissive-true")
  .option("--list", "list every documented rule", false)
  .action((ruleId: string | undefined, opts: { list?: boolean }) => {
    if (opts.list || !ruleId) {
      console.log(chalk.bold("\n  jimmy rules\n"));
      for (const r of listRules()) {
        console.log(`  ${chalk.cyan(r.id.padEnd(34))} ${chalk.gray(`[${r.severity}]`)} ${r.summary}`);
      }
      console.log(chalk.gray(`\n  run: jimmy explain <ruleId> for the why and the fix\n`));
      return;
    }
    const doc = explainRule(ruleId);
    if (!doc) {
      console.log(chalk.red(`[error] unknown rule "${ruleId}". try: jimmy explain --list`));
      process.exit(1);
    }
    console.log(chalk.bold(`\n  ${doc.id}`) + chalk.gray(`  [${doc.severity}]`));
    console.log(`\n  ${doc.summary}`);
    console.log(chalk.bold(`\n  why`));
    console.log(`  ${doc.why}`);
    console.log(chalk.bold(`\n  fix`));
    console.log(`  ${doc.fix}\n`);
  });

process.on("unhandledRejection", (reason) => {
  if (reason instanceof SafetyViolationError) {
    console.log(chalk.red(`[safety] ${reason.violation}: ${reason.message}`));
    process.exit(3);
  }
  console.log(chalk.red(`[error] ${reason instanceof Error ? reason.message : String(reason)}`));
  process.exit(4);
});

program.parse();
