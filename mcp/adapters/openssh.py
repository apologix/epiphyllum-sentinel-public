"""Adaptador OpenSSH para logs://ssh/auth (prioridad alta del Prompt Maestro).

Traslada la semántica del parser `ssh-auth` de backend/src/log_formats.rs
—mismo criterio para Failed/Accepted password, Accepted publickey e
Invalid user— y añade formatos que ese flujo no cubre pero el servicio
real emite: Failed publickey, intentos máximos excedidos, sesiones
pam_unix y desconexiones. El año del syslog se resuelve con la política
de base.resolve_syslog; sin IP o sin usuario válidos no se emite un
auth.* incompleto: el hecho queda solo como texto en el registro.
"""
import re

from . import base

PARSER_NAME = 'openssh-auth'
PARSER_VERSION = '1'

LINE = re.compile(
    r'^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) \S+ sshd\[\d+\]: (.*)$'
)
FAILED_PASSWORD = re.compile(
    r'^Failed password for (invalid user )?(\S+) from (\S+) port \d+ ssh2'
)
FAILED_PUBLICKEY = re.compile(
    r'^Failed publickey for (invalid user )?(\S+) from (\S+) port \d+ ssh2'
)
ACCEPTED = re.compile(
    r'^Accepted (password|publickey) for (\S+) from (\S+) port \d+ ssh2'
)
INVALID_USER = re.compile(r'^Invalid user (\S+) from (\S+)')
MAX_ATTEMPTS = re.compile(
    r'^error: maximum authentication attempts exceeded for '
    r'(invalid user )?(\S+) from (\S+) port \d+ ssh2'
)
SESSION_OPENED = re.compile(
    r'^pam_unix\(sshd:session\): session opened for user ([^\s(]+)'
)
SESSION_CLOSED = re.compile(
    r'^pam_unix\(sshd:session\): session closed for user ([^\s(]+)'
)
DISCONNECTED = re.compile(
    r'^Disconnected from (?:(?:authenticating )?user (\S+) )?(\S+) port \d+'
)


def _auth(event_type, level, timestamp, username, ip_text, method, invalid_user):
    ip = base.valid_ip(ip_text)
    if ip is None or not base.valid_username(username):
        return []
    attributes = {'auth_method': method, 'protocol': 'ssh'}
    if invalid_user:
        attributes['invalid_user'] = True
    return [base.event(
        event_type, 'auth', level, PARSER_NAME, PARSER_VERSION,
        timestamp=timestamp,
        timestamp_source='syslog_context_year' if timestamp else None,
        src_ip=ip, username=username, attributes=attributes,
    )]


def _notice(timestamp, username=None, ip_text=None):
    ip = base.valid_ip(ip_text) if ip_text else None
    return [base.event(
        'system.notice', 'system', 'info', PARSER_NAME, PARSER_VERSION,
        timestamp=timestamp,
        timestamp_source='syslog_context_year' if timestamp else None,
        src_ip=ip,
        username=username if base.valid_username(username or '') else None,
    )]


def adapt(line, captured_at):
    match = LINE.match(line.rstrip('\r\n'))
    if not match:
        return []
    month = base.MONTHS.get(match.group(1))
    if month is None:
        return []
    timestamp = base.resolve_syslog(
        month, int(match.group(2)), int(match.group(3)),
        int(match.group(4)), int(match.group(5)), captured_at,
    )
    message = match.group(6)
    failed = FAILED_PASSWORD.match(message)
    if failed:
        return _auth('auth.failed', 'warning', timestamp, failed.group(2),
                     failed.group(3), 'password', bool(failed.group(1)))
    failed = FAILED_PUBLICKEY.match(message)
    if failed:
        return _auth('auth.failed', 'warning', timestamp, failed.group(2),
                     failed.group(3), 'publickey', bool(failed.group(1)))
    accepted = ACCEPTED.match(message)
    if accepted:
        return _auth('auth.success', 'info', timestamp, accepted.group(2),
                     accepted.group(3), accepted.group(1), False)
    invalid = INVALID_USER.match(message)
    if invalid:
        return _auth('auth.failed', 'warning', timestamp, invalid.group(1),
                     invalid.group(2), 'password', True)
    attempts = MAX_ATTEMPTS.match(message)
    if attempts:
        return _auth('auth.failed', 'warning', timestamp, attempts.group(2),
                     attempts.group(3), 'password', bool(attempts.group(1)))
    opened = SESSION_OPENED.match(message)
    if opened:
        return _notice(timestamp, username=opened.group(1))
    closed = SESSION_CLOSED.match(message)
    if closed:
        return _notice(timestamp, username=closed.group(1))
    disconnected = DISCONNECTED.match(message)
    if disconnected:
        return _notice(timestamp, username=disconnected.group(1),
                       ip_text=disconnected.group(2))
    return []
