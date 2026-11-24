"""Adaptador Node.js: el productor emite JSON Lines (NDJSON) versionado.

Decisión de Allan (2026-11-22): JSON Lines es el formato oficial del
productor Node; no hay parser de texto libre. El contrato completo del
productor, con ejemplos, vive en planning/MCP-EVENT-CONTRACT.md
(«Contrato del productor Node.js»). En síntesis: un objeto JSON por
línea, schema_version 1, timestamp RFC 3339 obligatorio, `type` de la
lista cerrada y campos opcionales acotados, sin contraseñas ni tokens.

Lo que no cumple el contrato no produce evento: la línea queda como
evidencia textual en el registro, sin inventar campos ni «arreglarla» en
silencio. El adaptador es genérico para cualquier aplicación Node que
emita este formato; no conoce a ninguna aplicación concreta (la futura
Outsourcing Canario solo tendrá que producir estas líneas).
"""
import json
from datetime import datetime

from . import base

PARSER_NAME = 'node-json'
PARSER_VERSION = '1'

ALLOWED_KEYS = {
    'schema_version', 'timestamp', 'type', 'level', 'request_id', 'user',
    'src_ip', 'method', 'route', 'status', 'duration_ms', 'error_code',
    'operation', 'resource_id', 'organization', 'message',
}
LEVELS = {'info', 'warning', 'error'}
AUTH_TYPES = {
    'auth.login_failed': ('auth.failed', 'auth', 'warning'),
    'auth.login_success': ('auth.success', 'auth', 'info'),
}
ERROR_TYPES = {'app.error', 'dependency.error', 'db.error'}
NOTICE_TYPES = {
    'app.started', 'http.request', 'http.response', 'db.operation',
    'validation.error', 'input.rejected', 'session.created',
    'session.ended', 'authz.denied', 'authz.forbidden_resource',
    'rate_limited', 'auth.anomaly', 'authz.anomaly',
}
# Campos que viajan a attributes del evento derivado, con su límite.
ATTRIBUTE_FIELDS = (('request_id', 64), ('error_code', 32), ('operation', 32))


def adapt(line, captured_at):
    try:
        entry = json.loads(line)
    except (ValueError, TypeError):
        return []
    if not isinstance(entry, dict) or not set(entry) <= ALLOWED_KEYS:
        return []
    schema = entry.get('schema_version')
    if schema != 1 or isinstance(schema, bool):
        return []
    kind = entry.get('type')
    if kind in AUTH_TYPES:
        event_type, source, default_level = AUTH_TYPES[kind]
    elif kind in ERROR_TYPES:
        event_type, source, default_level = ('app.error', 'app', 'error')
    elif kind in NOTICE_TYPES:
        event_type, source, default_level = ('system.notice', 'system', 'info')
    else:
        return []
    raw_timestamp = entry.get('timestamp')
    if not isinstance(raw_timestamp, str):
        return []
    try:
        timestamp = datetime.fromisoformat(raw_timestamp.replace('Z', '+00:00'))
    except ValueError:
        return []
    if timestamp.tzinfo is None:
        return []
    level = entry.get('level', default_level)
    if level not in LEVELS:
        return []
    user = entry.get('user')
    if user is not None and not base.valid_username(user):
        return []
    ip = None
    if entry.get('src_ip') is not None:
        if not isinstance(entry['src_ip'], str):
            return []
        ip = base.valid_ip(entry['src_ip'])
        if ip is None:
            return []
    attributes = {}
    for key, limit in ATTRIBUTE_FIELDS:
        value = entry.get(key)
        if value is not None:
            if not isinstance(value, str) or not value or len(value) > limit:
                return []
            attributes[key] = value
    if event_type.startswith('auth.') and (ip is None or user is None):
        # Sin los mínimos que R1/R2 exigen, el hecho se conserva como
        # notice con lo disponible (§2.2.1), no como un auth.* incompleto.
        event_type, source, level = 'system.notice', 'system', 'info'
    return [base.event(
        event_type, source, level, PARSER_NAME, PARSER_VERSION,
        timestamp=timestamp, timestamp_source='producer_rfc3339',
        src_ip=ip, username=user, attributes=attributes or None,
    )]
