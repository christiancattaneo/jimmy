/**
 * Safety guard. Refuses to run jimmy on databases that look like production
 * unless the operator explicitly opts in. Also enforces statement timeouts and
 * a host allowlist.
 *
 * The threat model: a tired engineer points jimmy at $DATABASE_URL, that env
 * var still references prod, and a property-test mutation escapes its rollback
 * because the schema was somehow shared. The guard's job is to make that path
 * fail loudly before any query runs.
 */

export type SafetyMode = "read-only" | "test-schema" | "unrestricted";

export interface SafetyConfig {
  mode: SafetyMode;
  /** Fail if the database name matches any of these substrings. */
  forbiddenNameSubstrings: string[];
  /** Required substring or exact value the database name must contain when mode is `test-schema`. */
  testNameSubstrings: string[];
  /** Hosts permitted. Empty array means all hosts allowed. */
  allowedHosts: string[];
  /** Statement timeout for every connection, milliseconds. */
  statementTimeoutMs: number;
  /** When set, override safeties. Only honored for genuine emergencies. */
  override: boolean;
}

export const DEFAULT_SAFETY_CONFIG: SafetyConfig = {
  mode: "read-only",
  forbiddenNameSubstrings: ["prod", "production", "live", "primary", "master"],
  testNameSubstrings: ["test", "jimmy", "ci", "tmp", "scratch", "dev", "local"],
  allowedHosts: [],
  statementTimeoutMs: 30_000,
  override: false,
};

export class SafetyViolationError extends Error {
  constructor(
    public readonly violation: string,
    message: string,
  ) {
    super(message);
    this.name = "SafetyViolationError";
  }
}

export interface ConnectionShape {
  host: string;
  port: number;
  database: string;
  user: string;
}

/**
 * Parse a postgres connection string into its components without exposing the
 * password. Throws on malformed URLs.
 */
export function parseConnectionString(url: string): ConnectionShape & { password: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (e) {
    throw new SafetyViolationError(
      "invalid-url",
      `Could not parse connection string: ${(e as Error).message}`,
    );
  }
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new SafetyViolationError(
      "unsupported-protocol",
      `Unsupported protocol: ${parsed.protocol}. Only postgres:// is supported.`,
    );
  }
  const database = parsed.pathname.replace(/^\//, "");
  if (!database) {
    throw new SafetyViolationError(
      "missing-database",
      "Connection string must include a database name in its path.",
    );
  }
  return {
    host: parsed.hostname || "localhost",
    port: parsed.port ? Number.parseInt(parsed.port, 10) : 5432,
    database,
    user: decodeURIComponent(parsed.username || ""),
    password: decodeURIComponent(parsed.password || ""),
  };
}

/**
 * The guard. Call `assertConnection` once before opening a pool. Call
 * `assertMutation` before any non-trivial mutation outside of a rollback.
 */
export class SafetyGuard {
  constructor(public readonly config: SafetyConfig = DEFAULT_SAFETY_CONFIG) {}

  assertConnection(shape: ConnectionShape): void {
    if (this.config.override) return;

    const lowered = shape.database.toLowerCase();
    for (const forbidden of this.config.forbiddenNameSubstrings) {
      if (lowered.includes(forbidden.toLowerCase())) {
        throw new SafetyViolationError(
          "production-name",
          `Database name "${shape.database}" contains forbidden substring "${forbidden}". ` +
            `Pass --i-know-what-im-doing to override (you almost certainly should not).`,
        );
      }
    }

    if (this.config.allowedHosts.length > 0) {
      if (!this.config.allowedHosts.includes(shape.host)) {
        throw new SafetyViolationError(
          "host-not-allowed",
          `Host "${shape.host}" is not in allowlist [${this.config.allowedHosts.join(", ")}].`,
        );
      }
    }
  }

  /**
   * Mutating workloads (rls fuzz, anomaly probes) need a database that looks
   * like a test database. Refuse otherwise.
   */
  assertMutation(shape: ConnectionShape): void {
    if (this.config.override) return;
    if (this.config.mode === "read-only") {
      throw new SafetyViolationError(
        "read-only-mode",
        "Safety mode is read-only. Cannot mutate. Use --mode test-schema or --mode unrestricted.",
      );
    }
    if (this.config.mode === "test-schema") {
      const lowered = shape.database.toLowerCase();
      const looksLikeTest = this.config.testNameSubstrings.some((s) => lowered.includes(s));
      if (!looksLikeTest) {
        throw new SafetyViolationError(
          "non-test-database",
          `Database "${shape.database}" does not look like a test database. ` +
            `Expected one of: ${this.config.testNameSubstrings.join(", ")}.`,
        );
      }
    }
  }

  /** SQL fragment to apply to every new connection. */
  sessionInitSql(): string {
    return `SET statement_timeout = ${this.config.statementTimeoutMs}; SET lock_timeout = ${Math.min(this.config.statementTimeoutMs, 5000)}; SET idle_in_transaction_session_timeout = ${this.config.statementTimeoutMs};`;
  }
}
