#!/bin/sh
set -u
echo "-- servicios:"; systemctl is-active canario-api nginx mysql 2>/dev/null
echo "-- salud API:"; curl -s http://127.0.0.1:3001/api/v1/health/live; echo
curl -s http://127.0.0.1:3001/api/v1/health/ready; echo
echo "-- sitio:"; curl -s -o /dev/null -w "landing %{http_code}\n" http://127.0.0.1:8081/
echo "-- version.json Node (contrato MCP):"; cat /var/lib/epiphyllum-lab/logs/node/version.json 2>/dev/null || echo "PENDIENTE: revisar el drop-in de versión"
echo "-- últimas líneas app/security:"; tail -n 2 /var/lib/epiphyllum-lab/logs/node/app.log 2>/dev/null; tail -n 2 /var/lib/epiphyllum-lab/logs/node/security.log 2>/dev/null
