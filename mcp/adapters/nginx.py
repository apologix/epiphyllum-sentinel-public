"""Adaptador Nginx: access (JSON del laboratorio) y error log.

access reproduce la tabla de verdad de log_formats::parse_lab_access del
backend: 401 con auth básica y usuario → auth.failed; 2xx con auth básica
y usuario → auth.success; 5xx con upstream 5xx → app.error; el resto →
system.notice. Cuando el adaptador emite eventos válidos, el backend los
usa y NO corre su parser sobre el mismo registro (exclusión mutua); el
parser del backend queda como fallback para servidores sin adaptador y
no se elimina. La evidencia HTTP conserva método, ruta normalizada por el
servidor y estado en el objeto cerrado del contrato: un 200 jamás se
afirma como acceso autenticado sin la marca de auth básica, y la ruta
normalizada no se presenta como target crudo.

error: solo los niveles que log_formats marca como error
(error|crit|alert|emerg) producen app.error; el resto no produce evento.
Una línea de error no es un incidente: eso lo decide Sentinel.
"""
import json
import re
from datetime import datetime, timezone

from . import base

ACCESS_PARSER = ('nginx-access', '1')
ERROR_PARSER = ('nginx-error', '1')
METHODS = {'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'}
ACCESS_KEYS = {
    'timestamp', 'remote_addr', 'remote_user', 'method', 'path', 'status',
    'upstream_status', 'protected',
}
ERROR_LINE = re.compile(
    r'^(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2}) '
    r'\[(error|crit|alert|emerg|warn|notice|info|debug)\] '
)
ERROR_LEVELS = {'error', 'crit', 'alert', 'emerg'}


def _upstream_codes(text):
    codes = []
    for part in text.split(','):
        try:
            codes.append(int(part.strip()))
        except ValueError:
            continue
    return codes


def adapt_access(line, captured_at):
    try:
        entry = json.loads(line)
    except (ValueError, TypeError):
        return []
    if not isinstance(entry, dict) or set(entry) != ACCESS_KEYS:
        return []
    status = entry['status']
    method = entry['method']
    path = entry['path']
    protected = entry['protected']
    remote_user = entry['remote_user']
    upstream = entry['upstream_status']
    if (
        not isinstance(status, int) or isinstance(status, bool)
        or not 100 <= status <= 599
        or method not in METHODS
        or protected not in ('basic', 'no')
        or not isinstance(path, str) or not path.startswith('/')
        or len(path) > 1024
        or not isinstance(remote_user, str) or len(remote_user) > 64
        or not isinstance(upstream, str) or len(upstream) > 64
        or not isinstance(entry['timestamp'], str)
        or not isinstance(entry['remote_addr'], str)
    ):
        return []
    ip = base.valid_ip(entry['remote_addr'])
    if ip is None:
        return []
    try:
        timestamp = datetime.fromisoformat(
            entry['timestamp'].replace('Z', '+00:00')
        )
    except ValueError:
        return []
    if timestamp.tzinfo is None:
        return []
    user = remote_user if remote_user not in ('', '-') else None
    http = {
        'method': method,
        'normalized_path': path.split('?')[0],
        'status': status,
        'origin': 'server_normalized_only',
    }
    codes = _upstream_codes(upstream)
    attributes = {'upstream_status': codes[0]} if codes else None
    if protected == 'basic' and user is not None and status == 401:
        kind = ('auth.failed', 'auth', 'warning')
    elif protected == 'basic' and user is not None and 200 <= status < 300:
        kind = ('auth.success', 'auth', 'info')
    elif status >= 500 and any(500 <= code <= 599 for code in codes):
        kind = ('app.error', 'app', 'error')
    else:
        kind = ('system.notice', 'system', 'info')
    event_type, source, level = kind
    return [base.event(
        event_type, source, level, *ACCESS_PARSER,
        timestamp=timestamp, timestamp_source='producer_rfc3339',
        src_ip=ip, username=user, http=http, attributes=attributes,
    )]


def adapt_error(line, captured_at):
    match = ERROR_LINE.match(line)
    if not match or match.group(7) not in ERROR_LEVELS:
        return []
    try:
        timestamp = datetime(
            int(match.group(1)), int(match.group(2)), int(match.group(3)),
            int(match.group(4)), int(match.group(5)), int(match.group(6)),
            tzinfo=timezone.utc,
        )
    except ValueError:
        timestamp = None
    return [base.event(
        'app.error', 'app', 'error', *ERROR_PARSER,
        timestamp=timestamp,
        timestamp_source='producer_naive_utc' if timestamp else None,
    )]
