"""Compatibilidad del contrato MCP tras añadir derived_events (§19).

La página conserva su forma: registros originales con su identidad,
hashes, offsets y cursores intactos; derived_events es una clave
opcional más que un servidor viejo no emite y un backend viejo ignora.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

import server

SECRET = b'only-a-synthetic-test-token-123456'
BASE_KEYS = {'id', 'file_id', 'start', 'end', 'sha256', 'text'}

SSH_FAILED = 'Nov 22 01:02:03 lab sshd[812]: Failed password for invalid user admin from 192.168.122.1 port 51234 ssh2\n'
SSH_UNKNOWN = 'Nov 22 01:02:04 lab sshd[812]: Connection from 192.168.122.1 port 51234 on 192.168.122.10 port 22 rdomain ""\n'
ACCESS_OK = json.dumps({
    'timestamp': '2026-11-22T01:02:03Z', 'remote_addr': '192.168.122.1',
    'remote_user': 'alice', 'method': 'GET', 'path': '/secure/',
    'status': 401, 'upstream_status': '-', 'protected': 'basic',
}) + '\n'
AUDIT_LINE = '20261122 01:04:00,labhost,lab,192.168.122.1,21,7,QUERY,app,SELECT 1,0\n'


class ContractCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        for service, files in {
            'ssh': {'auth.log': SSH_FAILED + SSH_UNKNOWN},
            'nginx': {'access.log': ACCESS_OK, 'error.log': ''},
            'mysql': {'error.log': '', 'audit.log': AUDIT_LINE},
            'node': {'app.log': '', 'security.log': ''},
        }.items():
            directory = self.root / service
            directory.mkdir()
            for name, content in files.items():
                (directory / name).write_text(content)
        (self.root / 'ssh' / 'version.json').write_text(json.dumps({
            'service': 'ssh', 'version': '9.9p1', 'routes': [],
        }))

    def tearDown(self):
        self.dir.cleanup()

    def test_page_shape_and_derived_presence(self):
        page = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(page['schema_version'], 1)
        self.assertEqual(page['service']['product'], 'openbsd:openssh')
        self.assertEqual(page['service']['version'], '9.9p1')
        self.assertEqual(len(page['records']), 2)
        derived, plain = page['records']
        # El registro reconocido gana la clave opcional; el resto de su
        # forma es idéntica a la de siempre.
        self.assertEqual(set(derived), BASE_KEYS | {'derived_events'})
        self.assertEqual(derived['derived_events'][0]['event_type'], 'auth.failed')
        self.assertEqual(derived['text'], SSH_FAILED)
        # El registro sin interpretación sale exactamente como antes.
        self.assertEqual(set(plain), BASE_KEYS)
        self.assertEqual(plain['text'], SSH_UNKNOWN)

    def test_reread_keeps_record_and_event_identity(self):
        first = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        second = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(
            [r['id'] for r in first['records']],
            [r['id'] for r in second['records']],
        )
        self.assertEqual(
            first['records'][0]['derived_events'],
            second['records'][0]['derived_events'],
        )
        # La lectura incremental con cursor no repite registros.
        follow = server.batch(
            str(self.root), 'logs://ssh/auth', first['next_cursor'], SECRET
        )
        self.assertEqual(follow['records'], [])
        self.assertEqual(follow['continuity'], 'continuous')

    def test_nginx_access_derived_matches_backend_classification(self):
        page = server.batch(str(self.root), 'logs://nginx/access', None, SECRET)
        event = page['records'][0]['derived_events'][0]
        self.assertEqual(event['event_type'], 'auth.failed')
        self.assertEqual(event['http']['status'], 401)

    def test_audit_resource_stays_text_only(self):
        # Pendiente de validación en VM: ningún derivado, como hoy.
        page = server.batch(str(self.root), 'logs://mysql/audit', None, SECRET)
        self.assertEqual(len(page['records']), 1)
        self.assertEqual(set(page['records'][0]), BASE_KEYS)

    def test_empty_source_page_has_no_records(self):
        page = server.batch(str(self.root), 'logs://node/app', None, SECRET)
        self.assertEqual(page['records'], [])
        self.assertEqual(page['diagnostics'], [])


if __name__ == '__main__':
    unittest.main()
