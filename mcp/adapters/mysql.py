"""Adaptador MySQL: SOLO el error log, contra formatos oficiales documentados.

No se asume edición, plugin ni formato de la instalación real: la
auditoría de debian13-lab está PENDIENTE DE VALIDACIÓN EN VM
(procedimiento en mcp/docs/05-DIAGNOSTICO-MYSQL.md). Este adaptador cubre
únicamente formatos públicos e identificados:

- MySQL 8.0 Reference Manual, «The Error Log»: líneas
  `2026-11-22T01:02:03.123456Z 12 [ERROR] [MY-012345] [Server] mensaje`
  (timestamp ISO en UTC, prioridad [System]/[Warning]/[ERROR]/[Note] y
  código [MY-xxxxxx] opcional). El timestamp trae zona explícita (Z):
  viaja como producer_rfc3339.
- MariaDB Knowledge Base, «Error Log»: líneas
  `2026-11-22  1:02:03 12 [ERROR] mensaje`. Su timestamp es naive en la
  zona del servidor: NO se asume UTC, así que el evento no lleva
  timestamp (la hora de ingesta sigue siendo el reloj del detector).

El error log y la auditoría SQL son canales separados y jamás se asume
que el error log contiene consultas. Nada aquí afirma inyección SQL: una
operación observada no es un ataque.
"""
import re
from datetime import datetime, timezone

from . import base

PARSER_NAME = 'mysql-error'
PARSER_VERSION = '1'
AUDIT_PARSER_NAME = 'mysql-audit'

MYSQL8_LINE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+\d+\s+'
    r'\[(System|Warning|ERROR|Note)\]\s+(?:\[(MY-\d+)\]\s+)?'
    r'(?:\[\w+\]\s+)?(.+)$'
)
MARIADB_LINE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{2}:\d{2}\s+\d+\s+'
    r'\[(ERROR|Warning|Note)\]\s+(.+)$'
)
ACCESS_DENIED = re.compile(r"Access denied for user '([^']+)'@'([^']+)'")


def _mysql8_timestamp(text):
    for fmt in ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ'):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def adapt_error(line, captured_at):
    line = line.rstrip('\r\n')
    match = MYSQL8_LINE.match(line)
    timestamp = None
    if match:
        priority, code, message = match.group(2), match.group(3), match.group(4)
        timestamp = _mysql8_timestamp(match.group(1))
    else:
        match = MARIADB_LINE.match(line)
        if not match:
            return []
        priority, code, message = match.group(1), None, match.group(2)
        # Timestamp naive en la zona del servidor: no se emite (docstring).
    denied = ACCESS_DENIED.search(message)
    if denied:
        user, host = denied.group(1), denied.group(2)
        ip = base.valid_ip(host)
        if ip is not None and base.valid_username(user):
            return [base.event(
                'auth.failed', 'auth', 'warning', PARSER_NAME, PARSER_VERSION,
                timestamp=timestamp,
                timestamp_source='producer_rfc3339' if timestamp else None,
                src_ip=ip, username=user,
                attributes={'auth_method': 'password'},
            )]
        return [base.event(
            'system.notice', 'system', 'info', PARSER_NAME, PARSER_VERSION,
            timestamp=timestamp,
            timestamp_source='producer_rfc3339' if timestamp else None,
            username=user if base.valid_username(user) else None,
        )]
    if priority == 'ERROR':
        attributes = {'error_code': code} if code else None
        return [base.event(
            'app.error', 'app', 'error', PARSER_NAME, PARSER_VERSION,
            timestamp=timestamp,
            timestamp_source='producer_rfc3339' if timestamp else None,
            attributes=attributes,
        )]
    return []


# Formato del registro del MariaDB Audit Plugin (MariaDB Knowledge Base,
# «Audit Plugin Log Format»): CSV con timestamp `YYYYMMDD HH:MM:SS`,
# servidor, usuario, host, id de conexión, id de sentencia, operación,
# base de datos, objeto y código de retorno. El campo «objeto» puede
# contener la consulta literal con datos sensibles: NUNCA se copia al
# evento; queda solo como evidencia en el registro original.
AUDIT_LINE = re.compile(
    r'^\d{8} \d{2}:\d{2}:\d{2},[^,]*,([^,]*),[^,]*,\d+,\d+,'
    r'([A-Z_]{1,32}),[^,]*,.*,\d+\s*$'
)


def audit_events(line, captured_at):
    """EXPERIMENTAL — pendiente de validación en la VM de Allan.

    Implementado y probado solo contra fixtures del formato documentado.
    NO está registrado en adapters.ADAPTERS: hasta identificar el
    producto, la edición y el mecanismo de auditoría real de
    debian13-lab, logs://mysql/audit sigue llegando como texto, como hoy.
    Una operación observada produce como máximo un system.notice con la
    operación y el usuario de base de datos (que el backend seudonimiza
    en attributes.db_user): jamás una afirmación de inyección SQL.
    El timestamp del formato es naive en la zona del servidor: no se
    emite, igual que en el error log de MariaDB.
    """
    match = AUDIT_LINE.match(line)
    if not match:
        return []
    user, operation = match.group(1), match.group(2)
    attributes = {'operation': operation}
    if base.valid_username(user):
        attributes['db_user'] = user
    return [base.event(
        'system.notice', 'system', 'info', AUDIT_PARSER_NAME, PARSER_VERSION,
        attributes=attributes,
    )]
