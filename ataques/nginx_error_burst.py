#!/usr/bin/env python3
"""Ráfaga HTTP 503 no destructiva contra el Nginx de laboratorio.

Solicita /error repetidamente para disparar R3 en logs://nginx/access.
No cambia configuración ni estado del servidor.
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request

from common import vm_ip


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=None, help="IP privada de la VM (o LAB_VM_IP)")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--path", default="/error")
    parser.add_argument("--requests", type=int, default=10, help="Solicitudes (máximo 30)")
    args = parser.parse_args()
    if not 1 <= args.requests <= 30:
        parser.error("--requests debe estar entre 1 y 30")
    ip = vm_ip(args.ip)
    url = f"http://{ip}:{args.port}{args.path}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    print(f"Objetivo HTTP: {url} · {args.requests} solicitud(es)")
    print("Solo laboratorio aislado. El resultado esperado es 503.\n")

    statuses: list[int] = []
    for index in range(1, args.requests + 1):
        try:
            with opener.open(url, timeout=4) as response:
                statuses.append(response.status)
        except urllib.error.HTTPError as error:
            statuses.append(error.code)
        except OSError as error:
            print(f"Error de conexión: {error}", file=sys.stderr)
            return 1
        print(f"{index:02d}: HTTP {statuses[-1]}")
    print("\nResumen:", ", ".join(map(str, statuses)))
    print("En Sentinel revisá Nginx laboratorio VM; R3 requiere 10 errores en 30 s.")
    return 0 if statuses.count(503) == len(statuses) else 2


if __name__ == "__main__":
    sys.exit(main())
