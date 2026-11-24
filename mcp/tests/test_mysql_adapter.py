"""Pruebas del adaptador MySQL (Prompt Maestro §11.6 y §18).

Solo formatos oficiales documentados, con fixtures identificados como
tales. La auditoría real de la VM está pendiente de validación: el parser
de auditoría se prueba aquí pero NO está activo en adapters.ADAPTERS.
"""
import json
import unittest
from datetime import datetime, timezone

from adapters import ADAPTERS, mysql

CAPTURED = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)

MYSQL8_ERROR = (
    '2026-11-22T01:02:03.123456Z 12 [ERROR] [MY-012345] [Server] '
    'Could not create unix socket lock file /var/run/mysqld/mysqld.sock.lock\n'
)
MYSQL8_DENIED = (
    "2026-11-22T01:03:00.000000Z 15 [Warning] [Server] "
    "Access denied for user 'lab'@'192.168.122.1' (using password: YES)\n"
)
MARIADB_ERROR = '2026-11-22  1:02:03 12 [ERROR] Could not open mysql.plugin table\n'
MARIADB_DENIED = (
    "2026-11-22  1:03:00 15 [Warning] Access denied for user "
    "'lab'@'192.168.122.1' (using password: YES)\n"
)
AUDIT_QUERY = (
    '20261122 01:04:00,labhost,lab,192.168.122.1,21,7,QUERY,app,'
    'SELECT password FROM users WHERE name = \'x\' OR \'1\'=\'1\',0\n'
)


class MySqlErrorLogTests(unittest.TestCase):
    def test_mysql8_error_with_code(self):
        events = mysql.adapt_error(MYSQL8_ERROR, CAPTURED)
        self.assertEqual(events[0]['event_type'], 'app.error')
        self.assertEqual(events[0]['attributes']['error_code'], 'MY-012345')
        self.assertEqual(events[0]['timestamp'], '2026-11-22T01:02:03Z')
        self.assertEqual(events[0]['timestamp_source'], 'producer_rfc3339')
        self.assertEqual(events[0]['parser_name'], 'mysql-error')

    def test_mysql8_system_and_note_produce_no_event(self):
        line = (
            '2026-11-22T01:00:00.000000Z 0 [System] [MY-010116] [Server] '
            '/usr/sbin/mysqld (mysqld 8.0.40) starting as process 1\n'
        )
        self.assertEqual(mysql.adapt_error(line, CAPTURED), [])

    def test_access_denied_with_ip_is_auth_failed(self):
        for fixture in (MYSQL8_DENIED, MARIADB_DENIED):
            events = mysql.adapt_error(fixture, CAPTURED)
            self.assertEqual(events[0]['event_type'], 'auth.failed', fixture)
            self.assertEqual(events[0]['username'], 'lab')
            self.assertEqual(events[0]['src_ip'], '192.168.122.1')
            self.assertEqual(
                events[0]['attributes']['auth_method'], 'password'
            )

    def test_access_denied_with_hostname_is_notice_not_auth(self):
        line = MYSQL8_DENIED.replace('192.168.122.1', 'gateway.local')
        events = mysql.adapt_error(line, CAPTURED)
        self.assertEqual(events[0]['event_type'], 'system.notice')

    def test_mariadb_error_has_no_timestamp(self):
        # El timestamp MariaDB es naive en la zona del servidor: no se
        # asume UTC y el evento sale sin timestamp.
        events = mysql.adapt_error(MARIADB_ERROR, CAPTURED)
        self.assertEqual(events[0]['event_type'], 'app.error')
        self.assertNotIn('timestamp', events[0])

    def test_unsupported_and_incomplete_formats(self):
        postgres = '2026-11-22 01:02:03 UTC [123] postgres@db FATAL:  password authentication failed\n'
        self.assertEqual(mysql.adapt_error(postgres, CAPTURED), [])
        self.assertEqual(mysql.adapt_error('2026-11-22T01:02:03Z 12 [ERROR]\n', CAPTURED), [])
        self.assertEqual(mysql.adapt_error('línea suelta\n', CAPTURED), [])

    def test_invalid_timestamp_keeps_error_without_timestamp(self):
        line = MYSQL8_ERROR.replace('2026-11-22T01:02:03.123456Z', '2026-13-22T01:02:03.123456Z')
        events = mysql.adapt_error(line, CAPTURED)
        self.assertEqual(events[0]['event_type'], 'app.error')
        self.assertNotIn('timestamp', events[0])


class MySqlAuditFixtureTests(unittest.TestCase):
    def test_audit_is_not_wired_into_the_server(self):
        self.assertNotIn('logs://mysql/audit', ADAPTERS)

    def test_connect_and_query_become_notices_without_literals(self):
        connect = (
            '20261122 01:03:00,labhost,lab,192.168.122.1,21,0,CONNECT,,,0\n'
        )
        events = mysql.audit_events(connect, CAPTURED)
        self.assertEqual(events[0]['event_type'], 'system.notice')
        self.assertEqual(events[0]['attributes']['operation'], 'CONNECT')
        self.assertEqual(events[0]['attributes']['db_user'], 'lab')
        query = mysql.audit_events(AUDIT_QUERY, CAPTURED)
        self.assertEqual(query[0]['event_type'], 'system.notice')
        self.assertEqual(query[0]['attributes']['operation'], 'QUERY')
        # La consulta literal y su contenido sensible jamás viajan en el
        # evento: solo queda como evidencia en el registro original.
        serialized = json.dumps(query)
        self.assertNotIn('SELECT', serialized)
        self.assertNotIn('password', serialized)

    def test_malformed_audit_line(self):
        self.assertEqual(mysql.audit_events('20261122,sin,formato\n', CAPTURED), [])
        self.assertEqual(mysql.audit_events('', CAPTURED), [])


if __name__ == '__main__':
    unittest.main()
