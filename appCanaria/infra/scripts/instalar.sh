#!/bin/sh
# Instalación en la VM (idempotente en lo seguro; NUNCA borra datos).
# Ejecutar como root en debian13-lab tras revisar docs/10-DESPLIEGUE-VM.md.
set -eu
REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
echo "== usuarios y directorios =="
id canario >/dev/null 2>&1 || useradd --system --home /srv/outsourcing-canario --shell /usr/sbin/nologin canario
install -d -m 0755 -o canario -g canario /srv/outsourcing-canario
install -d -m 0750 -o root -g adm /var/lib/epiphyllum-lab/logs/node /var/lib/epiphyllum-lab/logs/nginx /var/lib/epiphyllum-lab/logs/mysql
install -d -m 0750 -o canario -g canario /var/lib/canario/outbox
echo "== código =="
cp -a "$REPO_DIR/appCanaria/backend" /srv/outsourcing-canario/backend
cp -a "$REPO_DIR/appCanaria/lab-files" /srv/outsourcing-canario/lab-files
chown -R canario:canario /srv/outsourcing-canario
echo "== dependencias y build =="
cd /srv/outsourcing-canario/backend && sudo -u canario npm ci --omit=dev
cd "$REPO_DIR/appCanaria/frontend" && npm ci && npm run build
install -d -m 0755 /srv/outsourcing-canario/frontend
cp -a dist/. /srv/outsourcing-canario/frontend/
echo "== entorno (crear si no existe; completar contraseñas a mano) =="
install -d -m 0750 /etc/canario
[ -f /etc/canario/canario.env ] || { cp "$REPO_DIR/appCanaria/.env.example" /etc/canario/canario.env; chmod 0640 /etc/canario/canario.env; echo "EDITAR /etc/canario/canario.env con las contraseñas reales antes de arrancar"; }
echo "== systemd y nginx =="
install -m 0644 "$REPO_DIR/appCanaria/infra/systemd/canario-api.service" /etc/systemd/system/canario-api.service
install -d /etc/systemd/system/canario-api.service.d
install -m 0644 "$REPO_DIR/appCanaria/infra/systemd/canario-version.drop-in.conf" /etc/systemd/system/canario-api.service.d/10-version.conf
cp -a "$REPO_DIR/lab/vm-version/generate-version-json-node.sh" /usr/local/sbin/epiphyllum-generate-version-json-node && chmod 0755 /usr/local/sbin/epiphyllum-generate-version-json-node
install -m 0644 "$REPO_DIR/appCanaria/infra/nginx/canario.conf" /etc/nginx/sites-available/canario
ln -sf /etc/nginx/sites-available/canario /etc/nginx/sites-enabled/canario
systemctl daemon-reload
nginx -t
echo "== base de datos: ejecutar a mano (revisar antes) =="
echo "  mysql < appCanaria/infra/mysql/01-usuarios-y-base.sql   (con contraseñas reales)"
echo "  sudo -u canario CANARIO_ENV_FILE=/etc/canario/canario.env npm --prefix /srv/outsourcing-canario/backend run migrate"
echo "  sudo -u canario npm --prefix /srv/outsourcing-canario/backend run seed"
echo "== arranque =="
systemctl enable --now canario-api
systemctl reload nginx
echo "OK: verificar con scripts/verificar-salud.sh"
