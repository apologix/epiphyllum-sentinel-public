#!/bin/sh
# Doble clic o `./iniciar-laboratorio.sh`: levanta Sentinel con el
# laboratorio habilitado. Sin pasos manuales ni variables.
cd "$(dirname "$0")"
docker compose -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml up -d --build
echo "Sentinel del laboratorio iniciado: http://localhost:8080"
