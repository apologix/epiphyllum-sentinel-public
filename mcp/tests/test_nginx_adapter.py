"""Pruebas del adaptador Nginx (Prompt Maestro §9.4 y §18).

La tabla de verdad de access es la misma que el backend ejercita en
log_formats::tests::lab_http_does_not_turn_every_401_or_5xx_into_an_attack:
si ambos mecanismos discrepan en un caso, la exclusión mutua dejaría de
ser segura.
"""
import json
import unittest
from datetime import datetime, timezone

from adapters import nginx

CAPTURED = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)


def access_line(status, protected, user, upstream, path='/secure/', method='GET'):
    return json.dumps({
        'timestamp': '2026-11-22T01:02:03Z',
        'remote_addr': '192.168.122.1',
        'remote_user': user,
        'method': method,
        'path': path,
        'status': status,
        'upstream_status': upstream,
        'protected': protected,
    }) + '\n'


class NginxAccessTests(unittest.TestCase):
    def test_backend_truth_table(self):
        cases = [
            ((401, 'no', 'alice', '-'), 'system.notice'),
            ((401, 'basic', '-', '-'), 'system.notice'),
            ((401, 'basic', 'alice', '-'), 'auth.failed'),
            ((200, 'basic', 'alice', '200'), 'auth.success'),
            ((503, 'no', '-', '503'), 'app.error'),
            ((503, 'no', '-', '-'), 'system.notice'),
        ]
        for args, expected in cases:
            events = nginx.adapt_access(access_line(*args), CAPTURED)
            self.assertEqual(len(events), 1, args)
            self.assertEqual(events[0]['event_type'], expected, args)

    def test_http_evidence_and_query_stripping(self):
        events = nginx.adapt_access(
            access_line(200, 'basic', 'alice', '200', path='/secure/?next=/x'),
            CAPTURED,
        )
        http = events[0]['http']
        self.assertEqual(http['normalized_path'], '/secure/')
        self.assertEqual(http['origin'], 'server_normalized_only')
        self.assertEqual(http['status'], 200)
        self.assertEqual(events[0]['timestamp_source'], 'producer_rfc3339')

    def test_traversal_path_is_carried_not_claimed(self):
        # La ruta codificada viaja como evidencia en el objeto http; un 200
        # sin auth básica no se convierte en acceso ni en exfiltración.
        events = nginx.adapt_access(
            access_line(200, 'no', '-', '200', path='/files/%2e%2e/secret.txt'),
            CAPTURED,
        )
        self.assertEqual(events[0]['event_type'], 'system.notice')
        self.assertEqual(
            events[0]['http']['normalized_path'], '/files/%2e%2e/secret.txt'
        )

    def test_upstream_status_attribute(self):
        events = nginx.adapt_access(access_line(502, 'no', '-', '502, 503'), CAPTURED)
        self.assertEqual(events[0]['event_type'], 'app.error')
        self.assertEqual(events[0]['attributes']['upstream_status'], 502)

    def test_malformed_lines_produce_no_event(self):
        self.assertEqual(nginx.adapt_access('not json\n', CAPTURED), [])
        self.assertEqual(nginx.adapt_access('{"timestamp": 1}\n', CAPTURED), [])
        extra = json.loads(access_line(200, 'basic', 'alice', '200'))
        extra['extra'] = True
        self.assertEqual(nginx.adapt_access(json.dumps(extra) + '\n', CAPTURED), [])
        self.assertEqual(
            nginx.adapt_access(access_line(99, 'basic', 'alice', '200'), CAPTURED), []
        )
        self.assertEqual(
            nginx.adapt_access(access_line(401, 'digest', 'alice', '-'), CAPTURED), []
        )
        bad_ip = json.loads(access_line(401, 'basic', 'alice', '-'))
        bad_ip['remote_addr'] = 'example.com'
        self.assertEqual(nginx.adapt_access(json.dumps(bad_ip) + '\n', CAPTURED), [])


class NginxErrorTests(unittest.TestCase):
    def test_error_levels_become_app_error(self):
        line = '2026/11/22 01:02:03 [error] 812#812: *1 connect() failed (111: Connection refused) while connecting to upstream\n'
        events = nginx.adapt_error(line, CAPTURED)
        self.assertEqual(events[0]['event_type'], 'app.error')
        self.assertEqual(events[0]['timestamp'], '2026-11-22T01:02:03Z')
        self.assertEqual(events[0]['timestamp_source'], 'producer_naive_utc')
        self.assertEqual(events[0]['parser_name'], 'nginx-error')

    def test_upstream_timeout_and_missing_file(self):
        for text in (
            '2026/11/22 01:02:03 [error] 812#812: *1 upstream timed out (110: Connection timed out)\n',
            '2026/11/22 01:02:03 [error] 812#812: *1 open() "/srv/nope" failed (2: No such file or directory)\n',
            '2026/11/22 01:02:03 [emerg] 812#812: bind() to 0.0.0.0:80 failed (98: Address already in use)\n',
        ):
            self.assertEqual(
                nginx.adapt_error(text, CAPTURED)[0]['event_type'], 'app.error'
            )

    def test_non_error_levels_and_garbage_produce_no_event(self):
        self.assertEqual(
            nginx.adapt_error('2026/11/22 01:02:03 [warn] 812#812: aviso\n', CAPTURED),
            [],
        )
        self.assertEqual(
            nginx.adapt_error('2026/11/22 01:02:03 [notice] 812#812: signal process started\n', CAPTURED),
            [],
        )
        self.assertEqual(nginx.adapt_error('línea cualquiera\n', CAPTURED), [])

    def test_invalid_date_omits_timestamp(self):
        events = nginx.adapt_error(
            '2026/13/40 25:02:03 [error] 812#812: fallo\n', CAPTURED
        )
        self.assertEqual(events[0]['event_type'], 'app.error')
        self.assertNotIn('timestamp', events[0])


if __name__ == '__main__':
    unittest.main()
