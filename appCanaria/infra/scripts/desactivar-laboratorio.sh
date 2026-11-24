#!/bin/sh
set -eu
sed -i 's/^CANARIA_LAB_MODE=.*/CANARIA_LAB_MODE=safe/' /etc/canario/canario.env
systemctl restart canario-api
echo "Modo seguro restaurado."
