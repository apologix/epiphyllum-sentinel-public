#!/bin/sh
# Verifica prerrequisitos de la VM SIN cambiar nada.
set -u
fail=0
for cmd in node npm nginx mysql systemctl; do command -v $cmd >/dev/null 2>&1 || { echo "FALTA: $cmd"; fail=1; }; done
node --version 2>/dev/null | grep -Eq '^v(20|22|24)\.' || { echo "Node: se espera LTS 20/22/24"; fail=1; }
ss -ltn 2>/dev/null | grep -q ':8081 ' && echo "AVISO: el puerto 8081 ya está en uso (¿el sitio del laboratorio Sentinel? comparten puerto: ver docs/10 antes de seguir)" || echo "Puerto 8081 libre"
ss -ltn 2>/dev/null | grep -q ':3001 ' && { echo "AVISO: el puerto 3001 ya está en uso"; fail=1; } || echo "Puerto 3001 libre"
[ -d /var/lib/epiphyllum-lab/logs ] && echo "Directorio de logs del laboratorio presente" || { echo "FALTA: /var/lib/epiphyllum-lab/logs (lo crea la preparación MCP, docs/10)"; fail=1; }
exit $fail
