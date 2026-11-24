# Ataques controlados del laboratorio

Scripts **no destructivos** para generar evidencia en la VM aislada de
Epiphyllum Sentinel y comprobar detecciones en vivo.

> Solo para la VM autorizada del taller. Los scripts validan que el destino sea
> una IP privada o loopback. No los uses contra redes públicas, otros equipos ni
> servicios de Internet.

## Uso típico (copiar y pegar)

Ejecutá estos comandos **desde la raíz del repositorio**. Cambiá solo
`LAB_VM_IP` si la VM recibió otra IP por DHCP.

```sh
export LAB_VM_IP=192.168.122.210

python3 ataques/ssh_bruteforce.py --ip "$LAB_VM_IP" --attempts 6
python3 ataques/nginx_auth_fail.py --ip "$LAB_VM_IP" --attempts 6
python3 ataques/nginx_error_burst.py --ip "$LAB_VM_IP" --requests 10
python3 ataques/canario_sqli.py --ip "$LAB_VM_IP"
python3 ataques/monitor_sentinel.py --url http://localhost:8080
```

| Línea | Qué hace | Dónde mirar el resultado |
|---|---|---|
| `export LAB_VM_IP=...` | Fija la IP privada de la VM para todos los comandos | — |
| `ssh_bruteforce.py` | 6 intentos SSH con usuario inexistente | Incidencias → SSH → **R1 alta** |
| `nginx_auth_fail.py` | 6 respuestas `401` en `/secure/` | Incidencias → Nginx → **R1 alta** |
| `nginx_error_burst.py` | 10 respuestas `503` en `/error` | Incidencias → Nginx → **R3 media** |
| `canario_sqli.py` | SQLi de solo lectura en Canario `:8083` | Incidencias → Nginx/Node → hallazgos **AI** |
| `monitor_sentinel.py` | Lista las incidencias recientes por API | Consola |

Antes de ejecutar:

- Sentinel debe estar arriba en `http://localhost:8080`.
- Las fuentes MCP de SSH y Nginx deben estar activas en Sentinel.
- Para SSH tiene que estar activo el exportador
  `epiphyllum-ssh-auth-export.service` en la VM.
- Para Canario, el instructor debe habilitar el modo vulnerable; al terminar,
  restaurar `safe`.
- `monitor_sentinel.py` pide el secreto administrativo por variable
  `SENTINEL_ADMIN_SECRET` o por teclado. No lo imprime.

## Elegir la IP de la VM

Todos los scripts aceptan `--ip`. También podés fijarla una vez:

```sh
export LAB_VM_IP=192.168.122.210
```

La IP puede cambiar por DHCP. En el host del laboratorio:

```sh
/mnt/ssd/vms/debian/debianCloud/ip-debian13-lab.sh
virsh -c qemu:///system domifaddr debian13-lab
```

## Scripts

| Script | Objetivo | Efecto esperado |
|---|---|---|
| `ssh_bruteforce.py` | SSH en `:22` | 6 intentos rechazados → R1 alta en `logs://ssh/auth` |
| `nginx_auth_fail.py` | Nginx de laboratorio `:8081` | 6 respuestas 401 → R1 alta |
| `nginx_error_burst.py` | Nginx de laboratorio `:8081` | 10 respuestas 503 → R3 media |
| `canario_sqli.py` | Canario `:8083` | SQLi de solo lectura → hallazgos AI en Nginx/Node |
| `mysql_auth_fail.py` | MySQL local de la VM | 3 `Access denied` → eventos MySQL |
| `monitor_sentinel.py` | Sentinel local `:8080` | lista las incidencias recientes |

## SSH

```sh
python3 ataques/ssh_bruteforce.py --ip "$LAB_VM_IP" --attempts 6
```

Usa un usuario inexistente y `BatchMode=yes`; no prueba contraseñas reales ni
ejecuta comandos remotos. Requiere el exportador SSH activo en la VM
(`/etc/systemd/system/epiphyllum-ssh-auth-export.service`).

## Nginx

```sh
python3 ataques/nginx_auth_fail.py --ip "$LAB_VM_IP" --attempts 6
python3 ataques/nginx_error_burst.py --ip "$LAB_VM_IP" --requests 10
```

## SQLi en Canario

El instructor debe habilitar el modo vulnerable en la VM:

```sh
ssh apologix@"$LAB_VM_IP"
cd /ruta/al/repositorio   # raíz de esta copia en la VM
sudo ./appCanaria/infra/scripts/activar-laboratorio.sh 192.168.122.0/24
python3 ataques/canario_sqli.py --ip "$LAB_VM_IP"
```

Al terminar, restaurar el modo seguro:

```sh
sudo ./appCanaria/infra/scripts/desactivar-laboratorio.sh
```

Los payloads son `' OR '1'='1`, `'` y un `UNION SELECT` de lectura. No hay
`DROP`, `UPDATE`, `DELETE` ni cambios de datos.

## MySQL

MySQL no está expuesto fuera de la VM. Ejecutá el script dentro de la VM:

```sh
ssh apologix@"$LAB_VM_IP"
cd /ruta/al/repositorio   # raíz de esta copia en la VM
python3 ataques/mysql_auth_fail.py --host 127.0.0.1 --attempts 3
```

Genera `Access denied` en `mysql/error.log`. En Sentinel hoy queda como
`system.notice`, no como `auth.failed`; es una limitación conocida del mapeo
actual.

## Monitor

```sh
export SENTINEL_ADMIN_SECRET="$(docker --context default compose -p epiphyllum-sentinel \
  -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml \
  run --rm --no-deps --entrypoint cat secrets-init /secrets/admin_secret)"
python3 ataques/monitor_sentinel.py --url http://localhost:8080
unset SENTINEL_ADMIN_SECRET
```

También podés revisar **Incidencias**, **Eventos** y el modal **Revisión de
registros** en la interfaz.

## Resultado observado el 24/11/2026

- SSH: 6 `auth.failed` → **R1 alta** en el servicio SSH.
- Nginx 401: **R1 alta** + hallazgos AI.
- Nginx 503: hallazgos AI de error 500/502.
- SQLi Canario: **AI medium** en Nginx y **AI low** en Node; MySQL no generó
  incidencia porque la SQLi no llega a `mysql/error.log`.
- MySQL con contraseña incorrecta: 3 `system.notice`, sin incidencia.
