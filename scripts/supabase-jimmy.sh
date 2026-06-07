#!/usr/bin/env bash
# Thin Supabase integration: auto-detect the local Supabase database URL from
# `supabase status` and run jimmy against it. Use as a convenience wrapper, or
# symlink as `supabase-jimmy` on your PATH.
#
#   ./scripts/supabase-jimmy.sh scan --migrations-dir supabase/migrations
#   ./scripts/supabase-jimmy.sh rls fuzz
#
# Anything after the script name is passed through to jimmy; --db is filled in.

set -euo pipefail

if ! command -v supabase >/dev/null 2>&1; then
  echo "supabase CLI not found on PATH" >&2
  exit 1
fi

DB_URL="$(supabase status -o env 2>/dev/null | sed -n 's/^DB_URL="\(.*\)"$/\1/p')"
if [ -z "${DB_URL:-}" ]; then
  echo "could not read DB_URL from 'supabase status' (is the local stack running?)" >&2
  exit 1
fi

# jimmy from npx unless a local build is present
JIMMY="npx jimmy-db"
if [ -f "dist/cli/index.js" ]; then JIMMY="node dist/cli/index.js"; fi

exec $JIMMY "$@" --db "$DB_URL"
