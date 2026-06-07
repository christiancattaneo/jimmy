#!/usr/bin/env bash
# Dogfood jimmy against a local Supabase project by loading its migrations into
# a throwaway database, applying a minimal Supabase shim, then running every
# live check.
#
#   ./scripts/dogfood.sh <path-to-supabase-migrations-dir> [db-name]
#
# Example:
#   ./scripts/dogfood.sh ~/Projects/newzen/autocrm/supabase/migrations autocrm
#
# Creates jimmy_dogfood_<name>, loads the shim + every .sql migration in order,
# then runs scan + rls fuzz + anomalies. The database name always contains
# "jimmy" and "dogfood" so the safety guard permits the mutating probes.

set -uo pipefail

MIGRATIONS_DIR="${1:?usage: dogfood.sh <migrations-dir> [name]}"
NAME="${2:-$(basename "$(dirname "$(dirname "$MIGRATIONS_DIR")")")}"
DB_NAME="jimmy_dogfood_${NAME}"
ADMIN_URL="postgres://localhost:5432/postgres"
DB_URL="postgres://localhost:5432/${DB_NAME}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JIMMY="$(cd "$HERE/.." && pwd)/dist/cli/index.js"
OUT_DIR="${TMPDIR:-/tmp}/jimmy-dogfood-${NAME}"
mkdir -p "$OUT_DIR"

echo "==> resetting $DB_NAME"
psql "$ADMIN_URL" -c "DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE)" >/dev/null
psql "$ADMIN_URL" -c "CREATE DATABASE \"$DB_NAME\"" >/dev/null

echo "==> applying supabase shim"
psql "$DB_URL" -q -f "$HERE/supabase-shim.sql" >/dev/null 2>"$OUT_DIR/shim.err" \
  || { echo "shim failed, see $OUT_DIR/shim.err"; cat "$OUT_DIR/shim.err"; }

echo "==> loading migrations from $MIGRATIONS_DIR"
applied=0
failed=0
for f in $(ls "$MIGRATIONS_DIR"/*.sql | sort); do
  if psql "$DB_URL" -q -v ON_ERROR_STOP=1 -f "$f" >/dev/null 2>>"$OUT_DIR/migrate.err"; then
    applied=$((applied+1))
  else
    failed=$((failed+1))
    echo "    skipped (error): $(basename "$f")"
  fi
done
echo "    applied=$applied failed=$failed (migration errors in $OUT_DIR/migrate.err)"

echo "==> applying supabase default grants (anon/authenticated on public tables)"
# Real Supabase grants anon and authenticated on public tables by default and
# relies on RLS as the only gate. Replicate that so reachability-aware severities
# match production (otherwise RLS-off tables look unreachable here when they are
# not in production).
psql "$DB_URL" -q >/dev/null 2>&1 <<'SQL' || true
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon, authenticated;
SQL

echo "==> jimmy scan (rls audit + schema integrity)"
node "$JIMMY" scan --db "$DB_URL" --migrations-dir "$MIGRATIONS_DIR" \
  --output "$OUT_DIR/scan" --fail-on critical || true

echo "==> jimmy rls fuzz"
node "$JIMMY" rls fuzz --db "$DB_URL" --output "$OUT_DIR/fuzz" --fail-on critical || true

echo "==> jimmy anomalies"
node "$JIMMY" anomalies --db "$DB_URL" --output "$OUT_DIR/anomalies" --fail-on critical || true

echo "==> reports in $OUT_DIR"
ls -1 "$OUT_DIR"/*.md 2>/dev/null || true
