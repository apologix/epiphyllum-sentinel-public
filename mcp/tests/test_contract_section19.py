"""Pruebas de contrato §19 del Prompt Maestro contra el servidor real.

Complementa test_contract_compatibility.py: paginación (has_more), línea
parcial, rotación .1, gap, hash del registro original, versión inicial y
actualizada, metadatos ausentes o de otro servicio, y la superficie HTTP
(resources/list, resources/read, autorización, métodos denegados).

Todo corre contra server.batch y contra el Handler HTTP real (sin TLS:
el TLS lo aporta main() en la VM; aquí se prueba el protocolo).
"""
import hashlib
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

import server

SECRET = b'only-a-synthetic-test-token-123456'
SSH_LINE = 'Nov 22 01:02:03 lab sshd[812]: Failed password for user u{i} from 192.168.122.1 port 51234 ssh2\n'


def ssh_lines(count, start=0):
    return ''.join(SSH_LINE.format(i=i) for i in range(start, start + count))


class BatchContractTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        for service in ('ssh', 'nginx', 'mysql', 'node'):
            (self.root / service).mkdir()

    def tearDown(self):
        self.dir.cleanup()

    def write(self, service, name, content):
        (self.root / service / name).write_text(content)

    def test_has_more_and_incremental_page(self):
        self.write('ssh', 'auth.log', ssh_lines(130))
        first = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(len(first['records']), 128)
        self.assertTrue(first['has_more'])
        follow = server.batch(
            str(self.root), 'logs://ssh/auth', first['next_cursor'], SECRET
        )
        self.assertEqual(len(follow['records']), 2)
        self.assertFalse(follow['has_more'])
        self.assertEqual(follow['continuity'], 'continuous')
        ids = {r['id'] for r in first['records']} & {r['id'] for r in follow['records']}
        self.assertEqual(ids, set())

    def test_partial_line_waits_for_completion(self):
        path = self.root / 'ssh' / 'auth.log'
        path.write_text(SSH_LINE.format(i=1).rstrip('\n'))
        page = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(page['records'], [])
        with path.open('a') as file:
            file.write('\n' + SSH_LINE.format(i=2))
        follow = server.batch(
            str(self.root), 'logs://ssh/auth', page['next_cursor'], SECRET
        )
        self.assertEqual(len(follow['records']), 2)
        self.assertEqual(follow['records'][0]['text'], SSH_LINE.format(i=1))

    def test_record_hash_and_offsets_match_original(self):
        content = ssh_lines(3)
        self.write('ssh', 'auth.log', content)
        page = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        raw = content.encode()
        for record in page['records']:
            self.assertEqual(
                record['sha256'],
                hashlib.sha256(record['text'].encode()).hexdigest(),
            )
            self.assertEqual(
                raw[record['start']:record['end']].decode(),
                record['text'],
            )

    def test_rotation_drains_rotated_file_then_switches(self):
        # Estado previo: el cursor quedó a mitad del archivo que luego rota.
        path = self.root / 'ssh' / 'auth.log'
        path.write_text(ssh_lines(2))
        first = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(len(first['records']), 2)
        # Rotación: el activo pasa a .1 y nace un activo nuevo con 1 línea.
        path.rename(self.root / 'ssh' / 'auth.log.1')
        self.write('ssh', 'auth.log', ssh_lines(1, start=100))
        follow = server.batch(
            str(self.root), 'logs://ssh/auth', first['next_cursor'], SECRET
        )
        # Semántica real del servidor: la página de rotación drena el .1
        # (ya estaba al final) y REPOSICIONA el cursor sobre el activo
        # nuevo sin mezclar archivos en una misma página; la línea nueva
        # llega en la lectura siguiente, ya continua.
        self.assertEqual(follow['continuity'], 'rotation')
        self.assertEqual(follow['records'], [])
        third = server.batch(
            str(self.root), 'logs://ssh/auth', follow['next_cursor'], SECRET
        )
        self.assertEqual(third['continuity'], 'continuous')
        self.assertEqual(len(third['records']), 1)
        self.assertIn('u100', third['records'][0]['text'])

    def test_gap_when_cursor_file_disappears(self):
        path = self.root / 'ssh' / 'auth.log'
        path.write_text(ssh_lines(1))
        first = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        # El archivo del cursor desaparece y nace otro con otra identidad.
        path.unlink()
        self.write('ssh', 'auth.log', ssh_lines(1, start=50))
        gap = server.batch(
            str(self.root), 'logs://ssh/auth', first['next_cursor'], SECRET
        )
        self.assertEqual(gap['continuity'], 'gap')
        self.assertEqual(gap['records'], [])
        # En gap el cursor NO avanza: Sentinel bloquea para revisión.
        self.assertEqual(gap['next_cursor'], first['next_cursor'])
        self.assertIn('cursor_file_unavailable', gap['diagnostics'])

    def test_gap_when_file_is_truncated(self):
        path = self.root / 'ssh' / 'auth.log'
        path.write_text(ssh_lines(3))
        first = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        path.write_text(ssh_lines(1))
        gap = server.batch(
            str(self.root), 'logs://ssh/auth', first['next_cursor'], SECRET
        )
        self.assertEqual(gap['continuity'], 'gap')
        self.assertIn('file_truncated_or_modified', gap['diagnostics'])

    def test_version_update_is_published_on_next_read(self):
        self.write('ssh', 'auth.log', ssh_lines(1))
        self.write('ssh', 'version.json', json.dumps(
            {'service': 'ssh', 'version': '9.9p1', 'routes': []}))
        first = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(first['service']['version'], '9.9p1')
        self.assertEqual(first['service']['version_source'], 'service_status')
        self.write('ssh', 'version.json', json.dumps(
            {'service': 'ssh', 'version': '9.10p1', 'routes': []}))
        updated = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(updated['service']['version'], '9.10p1')

    def test_missing_metadata_reports_unavailable_with_product(self):
        self.write('node', 'app.log', '')
        page = server.batch(str(self.root), 'logs://node/app', None, SECRET)
        self.assertEqual(page['service']['product'], 'nodejs:node.js')
        self.assertIsNone(page['service']['version'])
        self.assertEqual(page['service']['version_source'], 'unavailable')
        self.assertEqual(page['service']['routes'], [])

    def test_mariadb_version_document_publishes_its_product(self):
        self.write('mysql', 'error.log', '')
        self.write('mysql', 'version.json', json.dumps({
            'service': 'mysql', 'product': 'mariadb:mariadb',
            'version': '11.8.9', 'routes': []}))
        page = server.batch(str(self.root), 'logs://mysql/error', None, SECRET)
        self.assertEqual(page['service']['product'], 'mariadb:mariadb')
        self.assertEqual(page['service']['version'], '11.8.9')
        self.assertEqual(page['service']['version_source'], 'service_status')

    def test_oracle_mysql_version_document_keeps_oracle_product(self):
        self.write('mysql', 'error.log', '')
        self.write('mysql', 'audit.log', '')
        self.write('mysql', 'version.json', json.dumps({
            'service': 'mysql', 'product': 'oracle:mysql',
            'version': '8.0.36', 'routes': []}))
        page = server.batch(str(self.root), 'logs://mysql/audit', None, SECRET)
        self.assertEqual(page['service']['product'], 'oracle:mysql')
        self.assertEqual(page['service']['version'], '8.0.36')

    def test_version_document_without_product_uses_default(self):
        # Documento previo al campo product: sigue siendo válido y publica
        # el producto por defecto del recurso.
        self.write('mysql', 'error.log', '')
        self.write('mysql', 'version.json', json.dumps({
            'service': 'mysql', 'version': '8.0.36', 'routes': []}))
        page = server.batch(str(self.root), 'logs://mysql/error', None, SECRET)
        self.assertEqual(page['service']['product'], 'oracle:mysql')
        self.assertEqual(page['service']['version'], '8.0.36')

    def test_version_document_with_foreign_product_is_unavailable(self):
        self.write('mysql', 'error.log', '')
        self.write('mysql', 'version.json', json.dumps({
            'service': 'mysql', 'product': 'f5:nginx',
            'version': '11.8.9', 'routes': []}))
        page = server.batch(str(self.root), 'logs://mysql/error', None, SECRET)
        self.assertEqual(page['service']['product'], 'oracle:mysql')
        self.assertIsNone(page['service']['version'])
        self.assertEqual(page['service']['version_source'], 'unavailable')

    def test_version_document_of_another_service_is_not_published(self):
        # Un version.json copiado al directorio equivocado (service=nginx
        # en el directorio ssh) no se publica como versión de ssh: el
        # servidor lo trata como no disponible y el backend jamás recibe
        # un producto que no sea el fijo del recurso.
        self.write('ssh', 'auth.log', ssh_lines(1))
        self.write('ssh', 'version.json', json.dumps(
            {'service': 'nginx', 'version': '1.26.3', 'routes': ['/']}))
        page = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(page['service']['product'], 'openbsd:openssh')
        self.assertIsNone(page['service']['version'])
        self.assertEqual(page['service']['version_source'], 'unavailable')

    def test_malformed_line_keeps_record_without_derived_events(self):
        self.write('ssh', 'auth.log', 'esto no es una línea sshd\n')
        page = server.batch(str(self.root), 'logs://ssh/auth', None, SECRET)
        self.assertEqual(len(page['records']), 1)
        self.assertNotIn('derived_events', page['records'][0])


class HttpContractTests(unittest.TestCase):
    """resources/list y resources/read por el Handler real (sin TLS)."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        (self.root / 'ssh').mkdir()
        (self.root / 'ssh' / 'auth.log').write_text(ssh_lines(1))
        self.previous_root = server.ROOT
        server.ROOT = str(self.root)
        self.httpd = server.Server(('127.0.0.1', 0), server.Handler, SECRET)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.ROOT = self.previous_root
        self.dir.cleanup()

    def post(self, method, uri=None, token=True):
        params = {'_meta': {}}
        if uri is not None:
            params['uri'] = uri
        body = json.dumps({'jsonrpc': '2.0', 'id': 7, 'method': method, 'params': params})
        headers = {
            'Content-Type': 'application/json',
            'MCP-Protocol-Version': server.VERSION,
            'Mcp-Method': method,
        }
        if uri is not None:
            headers['Mcp-Name'] = uri
        if token:
            headers['Authorization'] = 'Bearer ' + SECRET.decode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/mcp', body, headers)
        response = conn.getresponse()
        payload = json.loads(response.read())
        conn.close()
        return response.status, payload

    def test_resources_list(self):
        status, payload = self.post('resources/list')
        self.assertEqual(status, 200)
        uris = {r['uri'] for r in payload['result']['resources']}
        self.assertEqual(uris, set(server.SOURCES))

    def test_resources_read_returns_page(self):
        status, payload = self.post('resources/read', 'logs://ssh/auth')
        self.assertEqual(status, 200)
        page = json.loads(payload['result']['contents'][0]['text'])
        self.assertEqual(page['schema_version'], 1)
        self.assertEqual(len(page['records']), 1)
        self.assertEqual(page['service']['product'], 'openbsd:openssh')

    def test_unauthorized_without_token(self):
        status, _ = self.post('resources/list', token=False)
        self.assertEqual(status, 401)

    def test_tools_are_denied(self):
        status, _ = self.post('tools/list')
        self.assertEqual(status, 400)

    def test_unknown_resource_is_denied(self):
        status, _ = self.post('resources/read', 'logs://bogus/x')
        self.assertEqual(status, 400)


if __name__ == '__main__':
    unittest.main()
