#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1 && [ -S /var/run/docker.sock ]; then
  export DOCKER_HOST=unix:///var/run/docker.sock
fi

docker compose -f compose.yaml down
printf 'App detenida; los datos se conservaron.\n'
