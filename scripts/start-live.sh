#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1 && [ -S /var/run/docker.sock ]; then
  export DOCKER_HOST=unix:///var/run/docker.sock
fi

docker compose -f compose.yaml up -d --build --wait --wait-timeout 180

attempt=0
until curl -fsS --max-time 2 http://localhost:8080/api/v1/health/ready >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    printf 'La app inició, pero no respondió en http://localhost:8080/api/v1/health/ready\n' >&2
    exit 1
  fi
  sleep 2
done
printf 'App live disponible en http://localhost:8080. El límite opcional se configura en Ajustes.\n'
