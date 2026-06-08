/**
 * Secrets and PII at rest. A schema-level check (column names and types only,
 * no data is read) for values that should never sit in a plaintext column.
 *
 * Scoped tightly to keep the signal high:
 *   - passwords MUST be hashed. A `password`-shaped column that is not clearly
 *     a hash/digest is a critical finding.
 *   - secret material (api keys, tokens, private keys, client secrets) in a
 *     plaintext column should be moved to Vault or an encrypted column.
 *   - high-sensitivity PII (ssn, card number, cvv) in plaintext is flagged for
 *     review.
 *
 * Deliberately does NOT flag email/phone/name: those are routinely stored in
 * plaintext for legitimate reasons, and flagging them is pure noise.
 */

import type { ColumnInfo, SchemaSnapshot } from "../../db/introspect.js";
import { findingId, type Finding, type Severity } from "../../report/findings.js";

function isTextual(col: ColumnInfo): boolean {
  const t = col.dataType.toLowerCase();
  return t === "text" || t.startsWith("character") || t.startsWith("varchar") || t === "citext";
}

/**
 * A column that already looks like a hash/digest/encrypted blob is fine, and so
 * is a column that only holds a *reference* to a secret kept elsewhere (a Vault
 * key id, an ARN, a URL/URI, a foreign-key-style id). Those suffixes denote a
 * pointer, not the secret value, so flagging them is noise (e.g. `secret_ref`,
 * `api_key_id`, `token_arn`).
 */
function looksProtected(name: string): boolean {
  if (/(_hash|_digest|_hashed|_encrypted|_enc|_bcrypt|_argon2)$/i.test(name)) return true;
  if (/^hashed_/i.test(name)) return true;
  if (/(_ref|_id|_arn|_url|_uri)$/i.test(name)) return true;
  return false;
}

interface Pattern {
  rule: string;
  severity: Severity;
  label: string;
  test: (name: string) => boolean;
}

const PASSWORD_RE = /^(password|passwd|pwd|user_password|pass)$/i;
const SECRET_RE = /(api[_-]?key|secret|access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret|auth[_-]?token|session[_-]?token|webhook[_-]?secret)/i;
const PII_RE = /^(ssn|social_security|tax_id|national_id|card_number|credit_card|cc_number|cvv|cvc|passport_number|bank_account|iban|routing_number)$/i;

const PATTERNS: Pattern[] = [
  {
    rule: "pii.plaintext-password",
    severity: "critical",
    label: "password stored as plaintext (must be hashed with bcrypt/argon2)",
    test: (n) => PASSWORD_RE.test(n),
  },
  {
    rule: "pii.plaintext-secret",
    severity: "high",
    label: "secret material in a plaintext column (move to Vault or encrypt)",
    test: (n) => SECRET_RE.test(n),
  },
  {
    rule: "pii.plaintext-pii",
    severity: "medium",
    label: "high-sensitivity PII in a plaintext column (consider column encryption)",
    test: (n) => PII_RE.test(n),
  },
];

export function auditPii(snapshot: SchemaSnapshot): Finding[] {
  const findings: Finding[] = [];
  for (const col of snapshot.columns) {
    if (!isTextual(col)) continue;
    if (looksProtected(col.name)) continue;
    const fqn = `${col.schema}.${col.table}.${col.name}`;
    for (const p of PATTERNS) {
      if (!p.test(col.name)) continue;
      findings.push({
        id: findingId("schema", p.rule, fqn),
        category: "schema",
        ruleId: p.rule,
        severity: p.severity,
        title: `${fqn}: ${p.label}`,
        description:
          `Column ${col.name} on ${col.schema}.${col.table} is a ${col.dataType} and its name indicates ${p.label}. ` +
          `If the value is already protected, rename the column with a clear suffix (e.g. _hash, _encrypted) so this stops flagging.`,
        location: { schema: col.schema, table: col.table, column: col.name },
        evidence: { dataType: col.dataType },
      });
      break; // one finding per column
    }
  }
  return findings;
}

export const _internal = { looksProtected, isTextual, PASSWORD_RE, SECRET_RE, PII_RE };
