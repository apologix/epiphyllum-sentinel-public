"""Utilidades compartidas de los adaptadores MCP.

Un adaptador traduce UNA línea de log a cero o más eventos derivados del
contrato (planning/MCP-EVENT-CONTRACT.md §2.2). Nunca inventa campos: lo
que la línea no trae queda ausente. Nunca decide identidad, producto ni
versión del servicio: eso lo fija el servidor desde version.json y el mapa
fijo, y el backend lo valida contra la fuente autenticada.
"""
import ipaddress
from datetime import datetime, timedelta, timezone

MAX_USERNAME = 64

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def valid_ip(text):
    """La IP canónica si `text` parsea como IPv4/IPv6; si no, None."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def valid_username(text):
    return isinstance(text, str) and 0 < len(text) <= MAX_USERNAME


def rfc3339(moment):
    """Un datetime consciente como RFC 3339 en UTC con sufijo Z."""
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def resolve_syslog(month, day, hour, minute, second, captured_at):
    """Política de año para syslog sin año (§2.3 del contrato).

    Año del contexto de captura (el reloj del servidor MCP al leer la
    página); si la fecha resultante queda más de 24 h en el futuro (cruce
    dic→ene), se resta un año. Una fecha imposible (30 de febrero, hora 25)
    devuelve None: el adaptador omite el timestamp en vez de inventarlo.
    Los timestamps syslog se interpretan como UTC, igual que hace el
    backend en el flujo de archivos (NativeSource.timezone == 'UTC').
    """
    try:
        candidate = datetime(
            captured_at.year, month, day, hour, minute, second,
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    if candidate - captured_at > timedelta(hours=24):
        try:
            candidate = candidate.replace(year=candidate.year - 1)
        except ValueError:
            return None
    return candidate


def event(event_type, source, level, parser_name, parser_version, *,
          timestamp=None, timestamp_source=None, src_ip=None, username=None,
          http=None, attributes=None):
    """Construye un evento derivado solo con los campos presentes."""
    out = {
        'event_schema_version': 1,
        'event_type': event_type,
        'source': source,
        'level': level,
        'parser_name': parser_name,
        'parser_version': parser_version,
    }
    if timestamp is not None:
        out['timestamp'] = rfc3339(timestamp)
        out['timestamp_source'] = timestamp_source
    if src_ip is not None:
        out['src_ip'] = src_ip
    if username is not None:
        out['username'] = username
    if http is not None:
        out['http'] = http
    if attributes:
        out['attributes'] = attributes
    return out
