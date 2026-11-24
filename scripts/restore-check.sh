#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
DEST=${1:-artifacts/private/backup}
# Database validation name is fixed; never replace the running demo implicitly.
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U bootstrap -d postgres -c 'CREATE DATABASE sentinel_restore OWNER sentinel;'
docker compose exec -T postgres pg_restore -U bootstrap -d sentinel_restore < "$DEST/sentinel.dump"
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U bootstrap -d sentinel_restore -c "SELECT extversion FROM pg_extension WHERE extname='vector';"
