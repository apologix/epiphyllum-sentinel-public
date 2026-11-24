"""Utilidades compartidas por los ataques controlados del laboratorio.

Solo acepta destinos privados o loopback. El objetivo es la VM aislada del
taller, nunca una red pública ni un servicio de Internet.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

DEFAULT_VM_IP = os.getenv("LAB_VM_IP", "192.168.122.210")


def private_target(value: str) -> str:
    """Valida una IP privada/loopback y la devuelve como texto."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise SystemExit(f"Destino inválido: {value!r}. Usá una IPv4 privada del laboratorio.") from exc
    if not (address.is_private or address.is_loopback):
        raise SystemExit("DENEGADO: el destino no es una IP privada/loopback del laboratorio.")
    return str(address)


def vm_ip(value: str | None) -> str:
    return private_target(value or DEFAULT_VM_IP)


def private_url(value: str, default_port: int) -> str:
    """Valida una URL http(s) cuyo host sea privado/loopback o localhost."""
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit(f"URL inválida: {value!r}")
    host = parsed.hostname
    if host not in ("localhost",):
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise SystemExit("El host debe ser una IP privada o localhost.") from exc
        if not (address.is_private or address.is_loopback):
            raise SystemExit("DENEGADO: la URL no apunta a una red privada del laboratorio.")
    if not parsed.port:
        parsed = parsed._replace(netloc=f"{parsed.netloc}:{default_port}")
    return parsed.geturl()


def resolve_private(host: str) -> str:
    """Resuelve un hostname y exige que todas sus direcciones sean privadas."""
    if host == "localhost":
        return "127.0.0.1"
    addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    if not addresses or any(not (ipaddress.ip_address(a).is_private or ipaddress.ip_address(a).is_loopback) for a in addresses):
        raise SystemExit("DENEGADO: el hostname resuelve fuera de la red privada.")
    return host
