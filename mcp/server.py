#!/usr/bin/env python3
"""Servidor MCP de solo lectura para cuatro servicios de laboratorio aislado."""
import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import stat
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from adapters import ADAPTERS

ROOT = '/var/lib/epiphyllum-lab/logs'
SOURCES = {
    'logs://nginx/access': ('nginx', 'access.log', 'access.log.1'),
    'logs://nginx/error': ('nginx', 'error.log', 'error.log.1'),
    'logs://mysql/error': ('mysql', 'error.log', 'error.log.1'),
    'logs://mysql/audit': ('mysql', 'audit.log', 'audit.log.1'),
    'logs://node/app': ('node', 'app.log', 'app.log.1'),
    'logs://node/security': ('node', 'security.log', 'security.log.1'),
    'logs://ssh/auth': ('ssh', 'auth.log', 'auth.log.1'),
}
PRODUCTS = {
    'nginx': ('f5:nginx',),
    'mysql': ('oracle:mysql', 'mariadb:mariadb'),
    'node': ('nodejs:node.js',),
    'ssh': ('openbsd:openssh',),
}
VERSION = '2026-07-28'
MAX_LINE = 16384
MAX_BATCH = 128
MAX_BYTES = 65536


def encode_cursor(state, secret):
    data = json.dumps(state, sort_keys=True, separators=(',', ':')).encode()
    signature = hmac.digest(secret, data, 'sha256')
    return base64.urlsafe_b64encode(data + signature).decode().rstrip('=')


def decode_cursor(token, secret, name):
    if len(token) > 1024:
        raise ValueError('cursor_invalid')
    try:
        raw = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4))
        data, signature = raw[:-32], raw[-32:]
        if not hmac.compare_digest(signature, hmac.digest(secret, data, 'sha256')):
            raise ValueError('cursor_invalid')
        state = json.loads(data)
        if set(state) != {'source', 'device', 'inode', 'offset', 'anchor'} or state['source'] != name:
            raise ValueError('cursor_invalid')
        if any(type(state[k]) is not int or state[k] < 0 for k in ('device', 'inode', 'offset')):
            raise ValueError('cursor_invalid')
        if not isinstance(state['anchor'], str) or len(state['anchor']) != 64:
            raise ValueError('cursor_invalid')
        return state
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('cursor_invalid') from exc


def open_regular(root_fd, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('not_regular_file')
    return os.fdopen(fd, 'rb')


def anchor(file, offset):
    file.seek(max(0, offset - 64))
    return hashlib.sha256(file.read(min(64, offset))).hexdigest()


def batch(root, name, cursor, secret):
    """Lee desde una identidad física, devuelve huecos sin avanzar cursor."""
    if name not in SOURCES:
        raise ValueError('resource_invalid')
    service, *filenames = SOURCES[name]
    state = decode_cursor(cursor, secret, name) if cursor else None
    directory = os.open(os.path.join(root, service), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = []
    try:
        for filename in filenames:
            try:
                file = open_regular(directory, filename)
                opened.append(file)
            except FileNotFoundError:
                continue
        if not opened:
            raise ValueError('source_unavailable')
        selected = opened[0]
        continuity = 'initial' if state is None else 'continuous'
        offset = 0
        if state is not None:
            selected = next((f for f in opened if (os.fstat(f.fileno()).st_dev, os.fstat(f.fileno()).st_ino) == (state['device'], state['inode'])), None)
            if selected is None:
                return {'schema_version': 1, 'source': name.rsplit('/', 1)[-1], 'requested_cursor': cursor, 'records': [], 'next_cursor': cursor, 'has_more': False, 'continuity': 'gap', 'diagnostics': ['cursor_file_unavailable'], 'service': service_metadata(directory, service)}
            offset = state['offset']
            if os.fstat(selected.fileno()).st_size < offset or anchor(selected, offset) != state['anchor']:
                return {'schema_version': 1, 'source': name.rsplit('/', 1)[-1], 'requested_cursor': cursor, 'records': [], 'next_cursor': cursor, 'has_more': False, 'continuity': 'gap', 'diagnostics': ['file_truncated_or_modified'], 'service': service_metadata(directory, service)}
            if selected != opened[0]:
                continuity = 'rotation'
        selected.seek(offset)
        meta = os.fstat(selected.fileno())
        file_id = hashlib.sha256(f'{name}:{meta.st_dev}:{meta.st_ino}'.encode()).hexdigest()
        captured_at = datetime.now(timezone.utc)
        page_diagnostics = []
        records = []
        size = 0
        while len(records) < MAX_BATCH:
            start = selected.tell()
            raw = selected.readline(MAX_LINE + 1)
            if not raw:
                break
            if not raw.endswith(b'\n'):
                if len(raw) > MAX_LINE:
                    raise ValueError('record_too_large')
                selected.seek(start)
                break
            if len(raw) > MAX_LINE:
                raise ValueError('record_too_large')
            if size + len(raw) > MAX_BYTES:
                selected.seek(start)
                break
            text = raw.decode('utf-8')
            end = selected.tell()
            digest = hashlib.sha256(raw).hexdigest()
            identity = hashlib.sha256(f'{name}:{meta.st_dev}:{meta.st_ino}:{start}:{end}:{digest}'.encode()).hexdigest()
            record = {'id': identity, 'file_id': file_id, 'start': start, 'end': end, 'sha256': digest, 'text': text}
            # Adaptador del servicio: adjunta eventos derivados opcionales
            # al registro. Un fallo del adaptador jamás tumba la evidencia:
            # el registro sale como texto, con diagnóstico en la página.
            adapter = ADAPTERS.get(name)
            if adapter is not None:
                try:
                    derived = adapter(text, captured_at)
                except Exception:
                    derived = None
                    if 'adapter_failed' not in page_diagnostics:
                        page_diagnostics.append('adapter_failed')
                if derived:
                    record['derived_events'] = derived
            records.append(record)
            size += len(raw)
        end = selected.tell()
        # A retained rotated file must be drained before switching to the active file.
        if selected != opened[0] and end == meta.st_size:
            selected = opened[0]
            meta = os.fstat(selected.fileno())
            end = 0
        next_state = {'source': name, 'device': meta.st_dev, 'inode': meta.st_ino, 'offset': end, 'anchor': anchor(selected, end)}
        has_more = end < os.fstat(selected.fileno()).st_size
        return {'schema_version': 1, 'source': name.rsplit('/', 1)[-1], 'requested_cursor': cursor, 'records': records, 'next_cursor': encode_cursor(next_state, secret), 'has_more': has_more, 'continuity': continuity, 'diagnostics': page_diagnostics, 'service': service_metadata(directory, service)}
    finally:
        for file in opened:
            file.close()
        os.close(directory)


def service_metadata(directory, service):
    """Version generated by the service startup, read only from its fixed directory."""
    default = PRODUCTS[service][0]
    try:
        with open_regular(directory, 'version.json') as file:
            raw = file.read(2049)
        if len(raw) > 2048:
            raise ValueError('version_file_too_large')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError('version_invalid')
        product = value.get('product', default)
        version = value.get('version')
        if (value.get('service') != service
                or not isinstance(product, str) or product not in PRODUCTS[service]
                or not isinstance(version, str) or not (1 <= len(version) <= 64)):
            raise ValueError('version_invalid')
        if not all(c.isascii() and (c.isalnum() or c in '._+-') for c in version):
            raise ValueError('version_invalid')
        routes = value.get('routes', [])
        if not isinstance(routes, list) or len(routes) > 12 or any(
            not isinstance(route, str) or not (1 <= len(route) <= 80)
            or not route.startswith('/') or not all(c.isascii() and (c.isalnum() or c in '/_-') for c in route)
            for route in routes
        ):
            raise ValueError('routes_invalid')
        return {'id': service, 'product': product, 'version': version, 'version_source': 'service_status', 'routes': routes}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {'id': service, 'product': default, 'version': None, 'version_source': 'unavailable', 'routes': []}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8
    def __init__(self, address, handler, secret):
        super().__init__(address, handler)
        self.secret = secret
        self.slots = threading.BoundedSemaphore(4)
        self.rate_lock = threading.Lock()
        self.last_read = {}
    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise
    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        if isinstance(self.connection, ssl.SSLSocket):
            self.connection.do_handshake()
    def log_message(self, format, *args):
        pass  # Nunca registrar credenciales, cursores o registros.
    def reply(self, status, payload):
        data = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True
    def do_POST(self):
        self.connection.settimeout(5)
        supplied = self.headers.get('Authorization', '')
        expected = 'Bearer ' + self.server.secret.decode('ascii')
        if not hmac.compare_digest(supplied, expected):
            self.reply(401, {'error': 'unauthorized'})
            return
        try:
            if self.path != '/mcp' or self.headers.get('MCP-Protocol-Version') != VERSION:
                raise ValueError('request_invalid')
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 16384:
                raise ValueError('request_invalid')
            request = json.loads(self.rfile.read(length))
            if request.get('jsonrpc') != '2.0' or 'id' not in request or not isinstance(request.get('params'), dict):
                raise ValueError('request_invalid')
            method, params = request.get('method'), request['params']
            if self.headers.get('Mcp-Method') != method:
                raise ValueError('request_invalid')
            if method == 'resources/list':
                result = {'resultType': 'complete', 'resources': [{'uri': uri, 'name': uri.removeprefix('logs://')} for uri in SOURCES]}
            elif method == 'resources/read':
                uri = params.get('uri', '')
                if self.headers.get('Mcp-Name') != uri:
                    raise ValueError('request_invalid')
                parsed = urlsplit(uri)
                name = parsed.path.removeprefix('/')
                query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
                if parsed.scheme != 'logs' or parsed.fragment or set(query) - {'cursor'} or any(len(v) != 1 for v in query.values()) or f'logs://{parsed.netloc}/{name}' not in SOURCES:
                    raise ValueError('resource_invalid')
                with self.server.rate_lock:
                    now = time.monotonic()
                    resource = f'logs://{parsed.netloc}/{name}'
                    if now - self.server.last_read.get(resource, 0.0) < 0.2:
                        self.reply(429, {'error': 'rate_limited'})
                        return
                    self.server.last_read[resource] = now
                cursor = query.get('cursor', [None])[0]
                data = batch(ROOT, resource, cursor, self.server.secret)
                result = {'resultType': 'complete', 'contents': [{'uri': uri, 'mimeType': 'application/json', 'text': json.dumps(data, separators=(',', ':'), ensure_ascii=False)}]}
            else:
                raise ValueError('method_denied')
            self.reply(200, {'jsonrpc': '2.0', 'id': request['id'], 'result': result})
        except (ValueError, TypeError, KeyError, UnicodeError, OSError, socket.timeout):
            self.reply(400, {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32602, 'message': 'Solicitud o recurso inválido'}})


def main():
    token_file = os.environ['MCP_LAB_TOKEN_FILE']
    with open(token_file, 'rb') as file:
        token = file.read(257).strip()
    if not 32 <= len(token) <= 256 or any(c < 33 or c > 126 for c in token):
        raise ValueError('invalid_token')
    bind = os.environ.get('MCP_LAB_BIND', '127.0.0.1')
    server = Server((bind, int(os.environ.get('MCP_LAB_PORT', '443'))), Handler, token)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ['MCP_LAB_CERT'], os.environ['MCP_LAB_KEY'])
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == '__main__':
    main()
