/**
 * jimmy
 *
 * Tests the application's database layer for the gaps the other tools miss:
 * row-level security, multi-tenant isolation, transaction anomalies, schema
 * integrity, and migration safety.
 */

export {
  SafetyGuard,
  SafetyViolationError,
  DEFAULT_SAFETY_CONFIG,
  parseConnectionString,
  type SafetyConfig,
  type SafetyMode,
  type ConnectionShape,
} from "./safety/index.js";

export { connect, type JimmyConnection, type ConnectOptions } from "./db/connect.js";
export {
  introspect,
  type SchemaSnapshot,
  type TableInfo,
  type ColumnInfo,
  type ForeignKeyInfo,
  type UniqueConstraintInfo,
  type CheckConstraintInfo,
  type PolicyInfo,
  type RoleInfo,
  type IndexInfo,
  type FunctionInfo,
  type IntrospectOptions,
} from "./db/introspect.js";

export { auditRls, type RlsAuditOptions } from "./checks/rls/audit.js";
export { auditRpc, type RpcAuditOptions } from "./checks/rls/rpc.js";
export { auditStorage, type StorageAuditResult } from "./checks/storage/audit.js";
export { auditRealtime, type RealtimeAuditResult } from "./checks/realtime/audit.js";
export { auditCron, type CronAuditResult } from "./checks/cron/audit.js";
export { fuzzRls, adversarialTenantPair, type RlsFuzzOptions, type RlsFuzzResult } from "./checks/rls/fuzz.js";
export { auditSchema, type SchemaAuditOptions } from "./checks/schema/audit.js";
export { auditPii } from "./checks/pii/audit.js";
export { auditIndexes, type IndexAuditOptions, type IndexAuditResult } from "./checks/indexes/audit.js";
export { diffSnapshots } from "./checks/regression/diff.js";
export { crossCheckPrisma, parsePrismaSchema } from "./checks/orm/prisma.js";
export { proposeProperties } from "./checks/suggest/propose.js";
export { redactFindings, redactSql } from "./report/redact.js";
export {
  lintSqlText,
  compileCustomRules,
  type MigrationLintOptions,
  type Rule,
  type CustomMigrationRule,
} from "./checks/migrations/lint.js";
export { lintFile, lintDirectory } from "./checks/migrations/lint-fs.js";
export {
  runAnomalyProbes,
  recommendIsolationLevel,
  ALL_ISOLATION_LEVELS,
  type AnomaliesOptions,
  type AnomaliesResult,
  type AnomalyName,
  type IsolationLevel,
  type ProbeResult,
} from "./checks/anomalies/probes.js";
export {
  templatize,
  detectNplusOne,
  detectNplusOneFromTrace,
  parseTrace,
  readTrace,
  pgStatStatementsAvailable,
  readPgStatStatements,
  readQueryLog,
  type NplusoneOptions,
  type QueryStat,
  type TraceEntry,
} from "./checks/nplusone/detect.js";

export {
  buildReport,
  reportToJson,
  reportToMarkdown,
  reportToSarif,
  reportToHtml,
  type JimmyReport,
  type ReportConfig,
  type ReportStats,
} from "./report/generate.js";
export {
  buildBaseline,
  applyBaseline,
  readBaseline,
  writeBaseline,
  type Baseline,
  type BaselineApplication,
} from "./report/baseline.js";
export {
  parseFailOn,
  anyFails,
  type FailOnSpec,
} from "./report/findings.js";
export {
  SEVERITY_ORDER,
  isAtOrAbove,
  findingId,
  type Finding,
  type Severity,
  type CheckCategory,
} from "./report/findings.js";
export { CATALOG, explainRule, listRules, type RuleDoc } from "./report/catalog.js";
export {
  loadConfig,
  applyDisabledRules,
  JimmyConfigSchema,
  DEFAULT_CONFIG_FILENAMES,
  type JimmyConfig,
} from "./config.js";
