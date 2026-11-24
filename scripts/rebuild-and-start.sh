#!/bin/sh
# Recompila backend/frontend y arranca Sentinel con el contexto, proyecto y
# Compose del laboratorio. No borra volúmenes ni toca PostgreSQL, embeddings,
# secretos, perfiles, fuentes ni la VM del MCP.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PROJECT=epiphyllum-sentinel
URL=http://localhost:8080
READY="$URL/api/v1/health/ready"
DEADLINE_SECONDS=180

compose() {
  docker --context default compose \
    -p "$PROJECT" \
    -f compose.yaml \
    -f compose.organized.yaml \
    -f compose.lab.example.yaml \
    "$@"
}

logs_hint() {
  printf 'Ver logs:\n  docker --context default compose -p %s -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml logs --tail 100 backend frontend\n' "$PROJECT" >&2
}

usage() {
  cat <<'EOF'
Uso: scripts/rebuild-and-start.sh [--live|--paused]

  Sin argumentos o --live  GENERATION_PAUSED=0. Arranque normal: la app abre
                           aunque todavía no haya API ni MCP. Cuando configures
                           y habilites el proveedor, los trabajos elegibles se
                           procesan sin reiniciar y sin tope obligatorio.
  --paused                 GENERATION_PAUSED=1. Ensayo de MCP y CVE sin
                           generación de IA.

El script compila backend y frontend antes de recrear contenedores. Si el
build falla, la instalación actual queda como estaba.
EOF
}

MODE=live
MODE_SET=0
for arg in "$@"; do
  case "$arg" in
    --live)
      [ "$MODE_SET" -eq 0 ] || { usage >&2; exit 2; }
      MODE=live
      MODE_SET=1
      ;;
    --paused)
      [ "$MODE_SET" -eq 0 ] || { usage >&2; exit 2; }
      MODE=paused
      MODE_SET=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Argumento no reconocido: %s\n\n' "$arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! command -v curl >/dev/null 2>&1; then
  printf 'curl es necesario para esperar la disponibilidad de Sentinel.\n' >&2
  exit 1
fi

is_running() {
  compose ps --status running --services 2>/dev/null | grep -qx "$1"
}

printf 'Compilando backend y frontend antes de tocar los contenedores...\n'
if ! compose build backend frontend; then
  printf 'El build falló. La instalación actual queda en ejecución sin cambios.\n' >&2
  logs_hint
  exit 1
fi

if [ "$MODE" = live ]; then
  PAUSE=0
else
  PAUSE=1
fi

if is_running backend && is_running frontend; then
  printf 'Instalación en ejecución: recreando solo backend y frontend...\n'
  if ! GENERATION_PAUSED="$PAUSE" compose up -d --no-deps backend frontend; then
    printf 'No se pudo recrear backend/frontend.\n' >&2
    logs_hint
    exit 1
  fi
else
  printf 'Instalación detenida: arrancando con sus dependencias...\n'
  if ! GENERATION_PAUSED="$PAUSE" compose up -d; then
    printf 'No se pudo arrancar Sentinel.\n' >&2
    logs_hint
    exit 1
  fi
fi

deadline=$(( $(date +%s) + DEADLINE_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsS --max-time 2 "$READY" >/dev/null 2>&1; then
    printf 'Modo efectivo: %s. Sentinel disponible en %s\n' "$MODE" "$URL"
    exit 0
  fi
  sleep 2
done

printf 'Modo efectivo: %s. Sentinel se inició pero no respondió en el endpoint de readiness dentro de %s segundos.\n' "$MODE" "$DEADLINE_SECONDS" >&2
logs_hint
exit 1
