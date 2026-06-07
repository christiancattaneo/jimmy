#!/usr/bin/env bash
# Create a throwaway database and the supabase-like roles jimmy's integration
# tests expect. Idempotent. Safe to run repeatedly.
#
#   ./scripts/setup-test-db.sh                  # uses postgres://localhost:5432/jimmy_test
#   JIMMY_TEST_DB=postgres://... ./scripts/setup-test-db.sh
#
# The integration suite reads JIMMY_TEST_DB. The database name must contain a
# test-shaped substring (jimmy's safety guard refuses to mutate otherwise).

set -euo pipefail

DB_URL="${JIMMY_TEST_DB:-postgres://localhost:5432/jimmy_test}"

# Strip the path to get an admin URL pointed at the default 'postgres' db.
ADMIN_URL="$(printf '%s' "$DB_URL" | sed -E 's#/[^/]+$#/postgres#')"
DB_NAME="$(printf '%s' "$DB_URL" | sed -E 's#.*/##')"

echo "creating database '$DB_NAME' (if missing)"
psql "$ADMIN_URL" -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1 \
  || psql "$ADMIN_URL" -c "CREATE DATABASE \"$DB_NAME\""

echo "ensuring supabase-like roles exist"
psql "$DB_URL" -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
END $$;
SQL

echo "done. run: JIMMY_TEST_DB=$DB_URL npm run test:integration"
