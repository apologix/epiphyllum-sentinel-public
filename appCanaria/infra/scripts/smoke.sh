#!/bin/sh
# Smoke tests HTTP contra la instalación (sin navegador).
set -u
B="${1:-http://127.0.0.1:8081}"
echo "landing: $(curl -s -o /dev/null -w '%{http_code}' $B/)"
echo "servicios: $(curl -s $B/api/v1/services | head -c 60)…"
echo "login malo: $(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/auth/login -H 'content-type: application/json' -d '{"email":"nadie@canario.example","password":"incorrecta"}')"
echo "contacto: $(curl -s -X POST $B/api/v1/contact -H 'content-type: application/json' -d '{"name":"Smoke","email":"smoke@empresa.example","message":"Prueba de humo"}')"
