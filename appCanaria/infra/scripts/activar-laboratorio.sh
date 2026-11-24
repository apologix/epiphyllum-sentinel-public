#!/bin/sh
# Activa el modo vulnerable SOLO con verificación de aislamiento.
# Uso: activar-laboratorio.sh 192.168.122.0/24
set -eu
CIDR="${1:?Uso: activar-laboratorio.sh <CIDR-privada-del-laboratorio>}"
case "$CIDR" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) : ;; *) echo "DENEGADO: $CIDR no es una red privada"; exit 1;; esac
ip -4 addr | grep -q "inet 192.168.122\.\|inet 10\.\|inet 172\." || { echo "DENEGADO: no se detecta interfaz privada de laboratorio"; exit 1; }
echo "Antes de continuar confirmá a mano: snapshot de la VM creado, firewall revisado, sin exposición pública (docs/11)."
printf "Escribí ACTIVAR para continuar: "; read -r r; [ "$r" = "ACTIVAR" ] || { echo "Cancelado"; exit 1; }
# Acepta líneas activas o comentadas para que el script sea idempotente.
sed -i -E 's/^#?[[:space:]]*CANARIA_LAB_MODE=.*/CANARIA_LAB_MODE=vulnerable/; s/^#?[[:space:]]*CANARIA_LAB_ISOLATED=.*/CANARIA_LAB_ISOLATED=1/' /etc/canario/canario.env
if grep -qE '^#?[[:space:]]*CANARIA_LAB_ALLOWED_CIDR=' /etc/canario/canario.env; then
  sed -i -E "s|^#?[[:space:]]*CANARIA_LAB_ALLOWED_CIDR=.*|CANARIA_LAB_ALLOWED_CIDR=$CIDR|" /etc/canario/canario.env
else
  echo "CANARIA_LAB_ALLOWED_CIDR=$CIDR" >> /etc/canario/canario.env
fi
systemctl restart canario-api
echo "Modo vulnerable ACTIVO para $CIDR. Al terminar: scripts/desactivar-laboratorio.sh y restaurar la VM."
