#!/bin/sh
# Backup de la base ficticia (mysqldump) con fecha; sin tocar Sentinel.
set -eu
DEST="${1:-/var/backups/canario}"; install -d -m 0700 "$DEST"
mysqldump --single-transaction canario > "$DEST/canario-$(date +%Y%m%d-%H%M%S).sql"
echo "Backup en $DEST"
