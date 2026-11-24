#!/usr/bin/env python3
"""Intentos de conexión MySQL con contraseña incorrecta (no destructivo).

Usa el cliente `mysql` ya instalado en la VM con `SELECT 1`, para que MariaDB
registre Access denied. MySQL no está expuesto fuera de la VM: ejecutalo dentro
de debian13-lab (por SSH) o contra un laboratorio que publique el puerto.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

from common import private_target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3306)
    parser.add_argument("--user", default="canario_lab_ro")
    parser.add_argument("--password", default="invalid-lab-password")
    parser.add_argument("--attempts", type=int, default=3, help="Intentos (máximo 10)")
    args = parser.parse_args()
    if not 1 <= args.attempts <= 10:
        parser.error("--attempts debe estar entre 1 y 10")
    if args.host != "localhost":
        private_target(args.host)
    if not shutil.which("mysql"):
        print("No se encontró el cliente mysql. Instalalo en la VM o ejecutá este script desde ella.", file=sys.stderr)
        return 1

    env = dict(os.environ)
    env["MYSQL_PWD"] = args.password
    print(f"Objetivo MySQL: {args.host}:{args.port} · usuario {args.user!r} · {args.attempts} intento(s)")
    print("Solo laboratorio aislado. Cada intento ejecuta SELECT 1 y debe fallar.\n")
    failures = 0
    for index in range(1, args.attempts + 1):
        result = subprocess.run(
            ["mysql", "--protocol=TCP", "-h", args.host, "-P", str(args.port), "-u", args.user,
             "--connect-timeout=2", "-e", "SELECT 1"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            print(f"{index:02d}: CONEXIÓN ACEPTADA (revisar credenciales del laboratorio)")
        else:
            failures += 1
            print(f"{index:02d}: rechazado")
    print(f"\nResumen: {failures} rechazo(s).")
    print("MariaDB escribe Access denied en mysql/error.log como Warning.")
    print("Si Sentinel solo muestra system.notice, falta mapear loopback a auth.failed y regla R1.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
