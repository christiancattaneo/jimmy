/**
 * Supabase storage audit. Storage objects live in `storage.objects`, grouped
 * into buckets in `storage.buckets`. The common real-world mistakes:
 *
 *   - a bucket marked public = true: every object in it is readable by anyone
 *     with the URL, no auth, forever. Sometimes intended (avatars), often not
 *     (invoices, uploads, user documents).
 *   - storage.objects with RLS disabled, or with a permissive USING(true)
 *     policy granted to anon/authenticated: the bucket's "public" flag becomes
 *     irrelevant because the row policy lets anyone list/read anyway.
 *
 * This check reads a little data (the bucket list), so it is its own module
 * rather than a pure snapshot transform. Strictly read-only.
 */

import type pg from "pg";
import { findingId, type Finding } from "../../report/findings.js";

type Client = pg.PoolClient | pg.Client;

interface BucketRow {
  id: string;
  name: string;
  public: boolean;
  file_size_limit: number | null;
  allowed_mime_types: string[] | null;
}

interface StoragePolicyRow {
  policyname: string;
  cmd: string;
  permissive: string;
  roles: string[];
  qual: string | null;
  with_check: string | null;
}

export interface StorageAuditResult {
  findings: Finding[];
  /** True if a storage schema was present (otherwise the check is a no-op). */
  storagePresent: boolean;
}

const PUBLIC_ROLES = new Set(["public", "anon", "authenticated"]);

function isTriviallyTrue(clause: string | null): boolean {
  if (clause === null) return false;
  const n = clause.trim().toLowerCase().replace(/\s+/g, " ");
  return n === "true" || n === "(true)" || n === "1=1" || n === "(1=1)" || n === "(1 = 1)";
}

export async function auditStorage(client: Client): Promise<StorageAuditResult> {
  const present = await client.query(
    `SELECT 1 FROM information_schema.tables WHERE table_schema = 'storage' AND table_name = 'buckets'`,
  );
  if ((present.rowCount ?? 0) === 0) {
    return { findings: [], storagePresent: false };
  }

  const findings: Finding[] = [];

  const buckets = await client.query<BucketRow>(
    `SELECT id, name, public, file_size_limit, allowed_mime_types FROM storage.buckets ORDER BY name`,
  );
  for (const b of buckets.rows) {
    if (b.public) {
      findings.push({
        id: findingId("rls-audit", "storage.public-bucket", b.id),
        category: "rls-audit",
        ruleId: "storage.public-bucket",
        severity: "medium",
        title: `Storage bucket "${b.name}" is public`,
        description:
          `Bucket "${b.name}" is public: every object in it is readable by anyone with the URL, with no authentication. ` +
          `Confirm it only holds genuinely public assets (avatars, logos). If it holds anything user-scoped or sensitive, make it private and serve via signed URLs.`,
        location: { schema: "storage", table: b.name },
        remediation: `UPDATE storage.buckets SET public = false WHERE id = '${b.id}';`,
        evidence: {
          fileSizeLimit: b.file_size_limit,
          allowedMimeTypes: b.allowed_mime_types,
        },
      });
    }
    if (b.file_size_limit === null) {
      findings.push({
        id: findingId("rls-audit", "storage.no-size-limit", b.id),
        category: "rls-audit",
        ruleId: "storage.no-size-limit",
        severity: "low",
        title: `Storage bucket "${b.name}" has no file size limit`,
        description:
          `Bucket "${b.name}" has no file_size_limit. An authenticated uploader can fill your storage (and bill) without bound. Set a per-bucket limit.`,
        location: { schema: "storage", table: b.name },
        remediation: `UPDATE storage.buckets SET file_size_limit = 5242880 WHERE id = '${b.id}'; -- 5 MB`,
      });
    }
  }

  // storage.objects RLS posture
  const objectsRls = await client.query<{ relrowsecurity: boolean }>(
    `SELECT c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'storage' AND c.relname = 'objects'`,
  );
  const rlsEnabled = (objectsRls.rows[0]?.relrowsecurity) ?? false;
  if (!rlsEnabled) {
    findings.push({
      id: findingId("rls-audit", "storage.objects-no-rls", "storage.objects"),
      category: "rls-audit",
      ruleId: "storage.objects-no-rls",
      severity: "high",
      title: "RLS is disabled on storage.objects",
      description:
        "storage.objects has row-level security disabled. Any role with table grants can list and read every object across every bucket regardless of the bucket's public flag.",
      location: { schema: "storage", table: "objects" },
      remediation: "ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;",
    });
  }

  const policies = await client.query<StoragePolicyRow>(
    `SELECT policyname, cmd, permissive, COALESCE(roles::text[], '{}'::text[]) AS roles, qual, with_check
       FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects'`,
  );
  for (const p of policies.rows) {
    const grantsPublic = (p.roles ?? []).some((r) => PUBLIC_ROLES.has(r.toLowerCase()));
    if (p.permissive === "PERMISSIVE" && grantsPublic && (isTriviallyTrue(p.qual) || isTriviallyTrue(p.with_check))) {
      findings.push({
        id: findingId("rls-audit", "storage.permissive-policy", p.policyname),
        category: "rls-audit",
        ruleId: "storage.permissive-policy",
        severity: "high",
        title: `Permissive storage policy "${p.policyname}" grants ${p.cmd} to ${p.roles.join(", ")} with USING(true)`,
        description:
          `Storage policy "${p.policyname}" is permissive, applies to public roles, and its predicate is trivially true. ` +
          `That lets those roles ${p.cmd} objects across all buckets. Scope it by bucket_id and owner.`,
        location: { schema: "storage", table: "objects", role: p.roles.join(",") },
        remediation:
          `-- scope to a bucket and the owner, e.g.:\n` +
          `-- USING ( bucket_id = 'avatars' AND owner = auth.uid() )`,
        evidence: { command: p.cmd, using: p.qual, withCheck: p.with_check },
      });
    }
  }

  return { findings, storagePresent: true };
}
