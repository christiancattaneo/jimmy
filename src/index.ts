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
export { fuzzRls, type RlsFuzzOptions, type RlsFuzzResult } from "./checks/rls/fuzz.js";
export { auditSchema, type SchemaAuditOptions } from "./checks/schema/audit.js";
export {
  lintFile,
  lintDirectory,
  lintSqlText,
  type MigrationLintOptions,
} from "./checks/migrations/lint.js";
export {
  runAnomalyProbes,
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
  pgStatStatementsAvailable,
  readPgStatStatements,
  readQueryLog,
  type NplusoneOptions,
  type QueryStat,
} from "./checks/nplusone/detect.js";

export {
  buildReport,
  reportToJson,
  reportToMarkdown,
  reportToSarif,
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
