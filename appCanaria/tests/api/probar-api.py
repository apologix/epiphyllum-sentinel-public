#!/usr/bin/env python3
"""Pruebas HTTP de la API SIN frontend (docs/12). Uso:
   python3 probar-api.py [base]   (base por defecto http://127.0.0.1:8081)
Sale con código != 0 si alguna comprobación falla."""
import json, sys, urllib.request, http.cookiejar
BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8081'
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
fails = []
def call(method, path, body=None, expect=None, label=''):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None, headers={'Content-Type': 'application/json'})
    try:
        with op.open(req) as r: status, data = r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        status, data = e.code, json.loads(e.read() or b'{}')
    ok = expect is None or status == expect
    print(('OK ' if ok else 'FALLO ') + f"{label or path}: HTTP {status} (esperado {expect})")
    if not ok: fails.append(label or path)
    return status, data
call('GET', '/api/v1/health/live', expect=200, label='1 salud')
call('GET', '/api/v1/services', expect=200, label='2 servicios')
call('POST', '/api/v1/contact', {'name': 'API', 'email': 'api@empresa.example', 'message': 'Prueba sin frontend'}, expect=201, label='3 contacto')
call('POST', '/api/v1/quotes', {'company': 'Empresa API', 'contact_name': 'Ana', 'email': 'ana@empresa.example', 'service_slug': 'ciberseguridad', 'problem': 'Necesitamos SOC'}, expect=201, label='4 propuesta')
call('GET', '/api/v1/jobs', expect=200, label='5 vacantes')
call('POST', '/api/v1/auth/login', {'email': 'cliente@novapagos.example', 'password': 'incorrecta'}, expect=401, label='6 login incorrecto')
call('POST', '/api/v1/auth/login', {'email': 'cliente@novapagos.example', 'password': 'CanarioDemo2026!'}, expect=200, label='7 login correcto (ajustar contraseña a la del entorno)')
call('GET', '/api/v1/projects', expect=200, label='8 proyectos del cliente')
call('GET', '/api/v1/projects/2', expect=403, label='9 IDOR bloqueado en modo seguro')
call('GET', '/api/v1/talent/search?q=Mar%C3%ADa', expect=200, label='10 búsqueda de talento')
call('GET', '/api/v1/documents/preview?name=../internal/interno-marcador.txt', expect=403, label='11 traversal bloqueado en modo seguro')
call('GET', '/api/v1/operations/summary', expect=403, label='12 operations denegado para rol cliente')
print('\nRESULTADO:', 'TODO OK' if not fails else f'FALLOS: {fails}')
sys.exit(1 if fails else 0)
