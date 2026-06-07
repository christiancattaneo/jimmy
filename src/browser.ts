/**
 * Browser entry. Exposes the migration linter for the web playground. Only the
 * pure, dependency-free pieces are included; nothing here touches the database,
 * the filesystem, or node built-ins, so it bundles cleanly for the browser.
 */

export { lintSqlText } from "./checks/migrations/lint.js";
export type { Finding, Severity } from "./report/findings.js";
