#!/usr/bin/env python3
"""Fallos de autenticación HTTP contra el Nginx del laboratorio (401).

Hace peticiones con Basic Auth incorrecta a /secure/ para disparar R1 en
logs://nginx/access. No explota ninguna vulnerabilidad ni modifica el servidor.
"""
from __future__ import annotations

import argparse
import base64
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
    parser.add_argument("--port", type=int, default=8081, help="Puerto del Nginx de laboratorio")
    parser.add_argument("--path", default="/secure/")
    parser.add_argument("--user", default="lab-user")
    parser.add_argument("--password", default="invalid-lab-password")
    parser.add_argument("--attempts", type=int, default=6, help="Intentos (máximo 20)")
    args = parser.parse_args()
    if not 1 <= args.attempts <= 20:
        parser.error("--attempts debe estar entre 1 y 20")
    ip = vm_ip(args.ip)
    url = f"http://{ip}:{args.port}{args.path}"
    token = base64.b64encode(f"{args.user}:{args.password}".encode()).decode("ascii")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    print(f"Objetivo HTTP: {url} · usuario {args.user!r} · {args.attempts} intento(s)")
    print("Solo laboratorio aislado. El resultado esperado es 401.\n")

    statuses: list[int] = []
    for index in range(1, args.attempts + 1):
        request = urllib.request.Request(url, headers={"Authorization": "Basic " + token})
        try:
            with opener.open(request, timeout=4) as response:
                statuses.append(response.status)
        except urllib.error.HTTPError as error:
            statuses.append(error.code)
        except OSError as error:
            print(f"Error de conexión: {error}", file=sys.stderr)
            return 1
        print(f"{index:02d}: HTTP {statuses[-1]}")
    print("\nResumen:", ", ".join(map(str, statuses)))
    print("En Sentinel revisá Nginx laboratorio VM; R1 requiere 5 fallos en 60 s.")
    return 0 if statuses.count(401) == len(statuses) else 2


if __name__ == "__main__":
    sys.exit(main())
