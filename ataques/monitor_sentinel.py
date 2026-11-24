#!/usr/bin/env python3
"""Monitor de solo lectura de incidencias recientes de Sentinel.

Pide el secreto administrativo por variable de entorno
SENTINEL_ADMIN_SECRET o por teclado (nunca lo imprime) y consulta /reports.
No crea solicitudes de IA ni modifica nada.
"""
from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    parsed = urlparse(args.url)
    if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        print("Solo se permite el Sentinel local (localhost/127.0.0.1).", file=sys.stderr)
        return 1
    secret = os.getenv("SENTINEL_ADMIN_SECRET") or getpass.getpass("Secreto administrativo: ")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base = args.url.rstrip("/")
    try:
        login = urllib.request.Request(
            base + "/api/v1/session",
            data=json.dumps({"secret": secret}).encode(),
            headers={"content-type": "application/json", "origin": base},
            method="POST",
        )
        with opener.open(login, timeout=8) as response:
            csrf = json.loads(response.read())["csrf_token"]
        request = urllib.request.Request(
            f"{base}/api/v1/reports?limit={max(1, min(50, args.limit))}",
            headers={"x-csrf-token": csrf},
        )
        with opener.open(request, timeout=8) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as error:
        print(f"Error HTTP {error.code}: revisá el secreto administrativo.", file=sys.stderr)
        return 1
    except (OSError, KeyError, json.JSONDecodeError) as error:
        print(f"No se pudo consultar Sentinel: {error}", file=sys.stderr)
        return 1
    items = data.get("items", [])
    print(f"Incidencias recientes ({len(items)}):")
    for item in items:
        print(f"- {item.get('opened_at', '?')} · {item.get('severity', '?')} · "
              f"{item.get('service') or 'servicio sin identificar'} · {item.get('title', 'sin título')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
