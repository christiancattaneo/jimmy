/**
 * Schema introspection. Reads pg_catalog and information_schema to produce a
 * deterministic snapshot of every table, column, constraint, policy, and role
 * relevant to a jimmy run.
 *
 * Everything here is read-only.
 */

import type pg from "pg";
type Client = pg.PoolClient | pg.Client;

export interface TableInfo {
  schema: string;
  name: string;
  /** True iff `relrowsecurity` is set on the table. */
  rlsEnabled: boolean;
  /** True iff `relforcerowsecurity` is set. */
  rlsForced: boolean;
  estimatedRows: number;
}

export interface ColumnInfo {
  schema: string;
  table: string;
  name: string;
  ordinal: number;
  dataType: string;
  isNullable: boolean;
  hasDefault: boolean;
  default: string | null;
}

export interface ForeignKeyInfo {
  schema: string;
  table: string;
  column: string;
  referencedSchema: string;
  referencedTable: string;
  referencedColumn: string;
  onDelete: string;
  onUpdate: string;
}

export interface UniqueConstraintInfo {
  schema: string;
  table: string;
  name: string;
  columns: string[];
  isPrimaryKey: boolean;
}

export interface CheckConstraintInfo {
  schema: string;
  table: string;
  name: string;
  expression: string;
}

export interface PolicyInfo {
  schema: string;
  table: string;
  name: string;
  /** PERMISSIVE | RESTRICTIVE */
  type: string;
  /** ALL | SELECT | INSERT | UPDATE | DELETE */
  command: string;
  roles: string[];
  /** USING clause expression. */
  using: string | null;
  /** WITH CHECK clause expression. */
  withCheck: string | null;
}

export interface RoleInfo {
  name: string;
  isSuperuser: boolean;
  canLogin: boolean;
  canBypassRls: boolean;
}

export interface IndexInfo {
  schema: string;
  table: string;
  name: string;
  /** Raw index expression text. */
  definition: string;
  isUnique: boolean;
  isPrimary: boolean;
}

export interface SchemaSnapshot {
  introspectedAt: string;
  tables: TableInfo[];
  columns: ColumnInfo[];
  foreignKeys: ForeignKeyInfo[];
  uniques: UniqueConstraintInfo[];
  checks: CheckConstraintInfo[];
  policies: PolicyInfo[];
  roles: RoleInfo[];
  indexes: IndexInfo[];
}

const DEFAULT_EXCLUDED_SCHEMAS = [
  "pg_catalog",
  "information_schema",
  "pg_toast",
  "pgsodium",
  "pgsodium_masks",
  "vault",
  "graphql",
  "graphql_public",
  "extensions",
  "realtime",
  "_realtime",
  "_analytics",
  "supabase_functions",
  "supabase_migrations",
  "net",
];

export interface IntrospectOptions {
  includeSchemas?: string[];
  excludeSchemas?: string[];
  includeAuthSchema?: boolean;
}

function buildSchemaFilter(opts: IntrospectOptions): { sql: string; params: string[] } {
  if (opts.includeSchemas && opts.includeSchemas.length > 0) {
    return {
      sql: `n.nspname = ANY($1::text[])`,
      params: [`{${opts.includeSchemas.join(",")}}`],
    };
  }
  const excluded = [...DEFAULT_EXCLUDED_SCHEMAS, ...(opts.excludeSchemas ?? [])];
  if (opts.includeAuthSchema !== true) {
    excluded.push("auth", "storage");
  }
  return {
    sql: `n.nspname <> ALL($1::text[]) AND n.nspname NOT LIKE 'pg_temp_%' AND n.nspname NOT LIKE 'pg_toast_temp_%'`,
    params: [`{${[...new Set(excluded)].join(",")}}`],
  };
}

export async function introspect(
  client: Client,
  opts: IntrospectOptions = {},
): Promise<SchemaSnapshot> {
  const filter = buildSchemaFilter(opts);

  const tablesSql = `
    SELECT n.nspname::text AS schema,
           c.relname::text AS name,
           c.relrowsecurity AS rls_enabled,
           c.relforcerowsecurity AS rls_forced,
           COALESCE(c.reltuples, 0)::bigint AS estimated_rows
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'r'
       AND ${filter.sql}
     ORDER BY n.nspname, c.relname
  `;
  const tablesResult = await client.query(tablesSql, filter.params);
  const tables: TableInfo[] = tablesResult.rows.map((r) => ({
    schema: r.schema,
    name: r.name,
    rlsEnabled: r.rls_enabled,
    rlsForced: r.rls_forced,
    estimatedRows: Number(r.estimated_rows ?? 0),
  }));

  const columnsSql = `
    SELECT n.nspname::text AS schema,
           c.relname::text AS table,
           a.attname::text AS name,
           a.attnum AS ordinal,
           pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
           NOT a.attnotnull AS is_nullable,
           a.atthasdef AS has_default,
           pg_get_expr(d.adbin, d.adrelid) AS default_expr
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
     WHERE c.relkind = 'r'
       AND a.attnum > 0
       AND NOT a.attisdropped
       AND ${filter.sql}
     ORDER BY n.nspname, c.relname, a.attnum
  `;
  const columnsResult = await client.query(columnsSql, filter.params);
  const columns: ColumnInfo[] = columnsResult.rows.map((r) => ({
    schema: r.schema,
    table: r.table,
    name: r.name,
    ordinal: r.ordinal,
    dataType: r.data_type,
    isNullable: r.is_nullable,
    hasDefault: r.has_default,
    default: r.default_expr,
  }));

  const fkSql = `
    SELECT n.nspname::text AS schema,
           c.relname::text AS table,
           att.attname::text AS column,
           fn.nspname::text AS referenced_schema,
           fc.relname::text AS referenced_table,
           fatt.attname::text AS referenced_column,
           con.confdeltype::text AS on_delete,
           con.confupdtype::text AS on_update
      FROM pg_constraint con
      JOIN pg_class c ON c.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_class fc ON fc.oid = con.confrelid
      JOIN pg_namespace fn ON fn.oid = fc.relnamespace
      JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
      JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = k.attnum
      JOIN unnest(con.confkey) WITH ORDINALITY AS fk(attnum, ord) ON fk.ord = k.ord
      JOIN pg_attribute fatt ON fatt.attrelid = con.confrelid AND fatt.attnum = fk.attnum
     WHERE con.contype = 'f'
       AND ${filter.sql}
     ORDER BY n.nspname, c.relname, k.ord
  `;
  const fkResult = await client.query(fkSql, filter.params);
  const foreignKeys: ForeignKeyInfo[] = fkResult.rows.map((r) => ({
    schema: r.schema,
    table: r.table,
    column: r.column,
    referencedSchema: r.referenced_schema,
    referencedTable: r.referenced_table,
    referencedColumn: r.referenced_column,
    onDelete: r.on_delete,
    onUpdate: r.on_update,
  }));

  const uniqueSql = `
    SELECT n.nspname::text AS schema,
           c.relname::text AS table,
           con.conname::text AS name,
           ARRAY(
             SELECT att.attname
               FROM unnest(con.conkey) k(attnum)
               JOIN pg_attribute att ON att.attrelid = c.oid AND att.attnum = k.attnum
           ) AS columns,
           con.contype = 'p' AS is_primary
      FROM pg_constraint con
      JOIN pg_class c ON c.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE con.contype IN ('p', 'u')
       AND ${filter.sql}
  `;
  const uniqueResult = await client.query(uniqueSql, filter.params);
  const uniques: UniqueConstraintInfo[] = uniqueResult.rows.map((r) => ({
    schema: r.schema,
    table: r.table,
    name: r.name,
    columns: r.columns,
    isPrimaryKey: r.is_primary,
  }));

  const checkSql = `
    SELECT n.nspname::text AS schema,
           c.relname::text AS table,
           con.conname::text AS name,
           pg_get_constraintdef(con.oid) AS expression
      FROM pg_constraint con
      JOIN pg_class c ON c.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE con.contype = 'c'
       AND ${filter.sql}
  `;
  const checkResult = await client.query(checkSql, filter.params);
  const checks: CheckConstraintInfo[] = checkResult.rows.map((r) => ({
    schema: r.schema,
    table: r.table,
    name: r.name,
    expression: r.expression,
  }));

  const policySql = `
    SELECT schemaname::text AS schema,
           tablename::text AS table,
           policyname::text AS name,
           permissive::text AS type,
           cmd::text AS command,
           COALESCE(roles, '{}'::text[]) AS roles,
           qual::text AS using_clause,
           with_check::text AS with_check
      FROM pg_policies
     WHERE schemaname <> ALL($1::text[])
  `;
  const policyResult = await client.query(policySql, filter.params);
  const policies: PolicyInfo[] = policyResult.rows.map((r) => ({
    schema: r.schema,
    table: r.table,
    name: r.name,
    type: r.type,
    command: r.command,
    roles: r.roles,
    using: r.using_clause,
    withCheck: r.with_check,
  }));

  const roleSql = `
    SELECT rolname::text AS name,
           rolsuper AS is_superuser,
           rolcanlogin AS can_login,
           rolbypassrls AS can_bypass_rls
      FROM pg_roles
  `;
  const roleResult = await client.query(roleSql);
  const roles: RoleInfo[] = roleResult.rows.map((r) => ({
    name: r.name,
    isSuperuser: r.is_superuser,
    canLogin: r.can_login,
    canBypassRls: r.can_bypass_rls,
  }));

  const indexSql = `
    SELECT n.nspname::text AS schema,
           c.relname::text AS table,
           ic.relname::text AS name,
           pg_get_indexdef(i.indexrelid) AS definition,
           i.indisunique AS is_unique,
           i.indisprimary AS is_primary
      FROM pg_index i
      JOIN pg_class c ON c.oid = i.indrelid
      JOIN pg_class ic ON ic.oid = i.indexrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'r'
       AND ${filter.sql}
  `;
  const indexResult = await client.query(indexSql, filter.params);
  const indexes: IndexInfo[] = indexResult.rows.map((r) => ({
    schema: r.schema,
    table: r.table,
    name: r.name,
    definition: r.definition,
    isUnique: r.is_unique,
    isPrimary: r.is_primary,
  }));

  return {
    introspectedAt: new Date().toISOString(),
    tables,
    columns,
    foreignKeys,
    uniques,
    checks,
    policies,
    roles,
    indexes,
  };
}
