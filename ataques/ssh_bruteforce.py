#!/usr/bin/env python3
"""Fuerza bruta SSH acotada y no destructiva contra la VM del laboratorio.

Genera intentos con un usuario inexistente y autenticación por clave
deshabilitada en modo BatchMode. No prueba contraseñas reales ni ejecuta nada
en el host remoto. Pensado para disparar R1 en el recurso logs://ssh/auth.
"""
from __future__ import annotations

import argparse
import subprocess
import sys

from common import vm_ip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=None, help="IP privada de la VM (o LAB_VM_IP)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="intruso-prueba", help="Usuario inexistente de laboratorio")
    parser.add_argument("--attempts", type=int, default=6, help="Intentos (máximo 20)")
    parser.add_argument("--timeout", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.attempts <= 20:
        parser.error("--attempts debe estar entre 1 y 20")
    ip = vm_ip(args.ip)
    print(f"Objetivo SSH: {ip}:{args.port} · usuario {args.user!r} · {args.attempts} intento(s)")
    print("Solo laboratorio aislado. Los intentos deben ser rechazados.\n")

    failures = 0
    accepted = 0
    for index in range(1, args.attempts + 1):
        command = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={args.timeout}",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(args.port),
            f"{args.user}@{ip}",
            "true",
        ]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            accepted += 1
            print(f"{index:02d}: ACCESO ACEPTADO (revisar: no debería ocurrir con este usuario)")
        else:
            failures += 1
            print(f"{index:02d}: rechazado")
    print(f"\nResumen: {failures} rechazado(s), {accepted} aceptado(s).")
    print("En Sentinel revisá Incidencias y Eventos del servicio SSH; R1 requiere 5 fallos en 60 s.")
    return 0 if accepted == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
