#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
DEST=${1:-artifacts/private/backup}
mkdir -p "$DEST"
umask 077
docker compose exec -T postgres pg_dump -U bootstrap -d sentinel -Fc > "$DEST/sentinel.dump"
docker compose run --rm --no-deps --user 0 --entrypoint tar generator -C /data/logs -cf - . > "$DEST/demo-logs.tar"
echo "Backup escrito en $DEST. MASTER_KEY y ADMIN_SECRET se conservan aparte en private-secrets o .env privado migrado; este backup no los contiene."
