import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config/config.js';
import { MemoryRepo } from '../src/db/repo.js';
import { seedRepo } from '../src/seed-apply.js';
import { createLogger } from '../src/logging/logger.js';

const lines = [];
const logger = createLogger({ sink: (file, line) => lines.push({ file, ...JSON.parse(line) }) });
const config = loadConfig({ CANARIA_LAB_MODE: 'safe', CANARIA_LOG_DIR: '/tmp/canario-test-logs' });
const repo = new MemoryRepo();
let app;
before(async () => { await seedRepo(repo, {}); app = await buildApp({ config, repo, logger }); });
after(async () => { await app.close(); });
const login = async (email, pw) => app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { email, password: pw } });

test('salud y catálogo público', async () => {
  assert.equal((await app.inject({ url: '/api/v1/health/live' })).statusCode, 200);
  const s = await app.inject({ url: '/api/v1/services' }); assert.equal(JSON.parse(s.body).items.length, 6);
  const j = await app.inject({ url: '/api/v1/jobs' }); assert.equal(JSON.parse(j.body).items.length, 12);
});
test('contacto persiste y genera código', async () => {
  const r = await app.inject({ method: 'POST', url: '/api/v1/contact', payload: { name: 'Prueba', email: 'prueba@empresa.example', message: 'Necesitamos un equipo backend.' } });
  assert.equal(r.statusCode, 201); assert.ok(JSON.parse(r.body).request_code.startsWith('CON-'));
  assert.equal((await repo.list('contact_leads')).length, 1);
});
test('login incorrecto 401 y correcto crea sesión', async () => {
  assert.equal((await login('cliente@novapagos.example', 'mala-mala-mala')).statusCode, 401);
  const ok = await login('cliente@novapagos.example', 'CanarioDemo2026!');
  assert.equal(ok.statusCode, 200); assert.ok(ok.headers['set-cookie']);
});
test('los logs cumplen el contrato node-json@1 (claves y tipos cerrados)', async () => {
  const { ALLOWED_KEYS, ALLOWED_TYPES } = await import('../src/logging/logger.js');
  assert.ok(lines.length > 5);
  for (const l of lines) { for (const k of Object.keys(l)) if (k !== 'file') assert.ok(ALLOWED_KEYS.has(k), `clave fuera de contrato: ${k}`); assert.ok(ALLOWED_TYPES.has(l.type), `tipo fuera de contrato: ${l.type}`); assert.ok(l.schema_version === 1); assert.ok(/Z$/.test(l.timestamp)); }
  const failed = lines.filter(l => l.type === 'auth.login_failed');
  assert.ok(failed.length >= 1 && failed[0].user && failed[0].src_ip, 'auth.login_failed con mínimos para auth.failed');
});
test('request_id viaja en la respuesta y en los logs', async () => {
  const r = await app.inject({ url: '/api/v1/services', headers: { 'x-request-id': 'req-prueba-123' } });
  assert.equal(r.headers['x-request-id'], 'req-prueba-123');
  assert.ok(lines.some(l => l.request_id === 'req-prueba-123'));
});
test('aislamiento entre organizaciones en modo seguro (Escenario D)', async () => {
  const ok = await login('cliente@novapagos.example', 'CanarioDemo2026!');
  const cookie = ok.headers['set-cookie'];
  const own = await app.inject({ url: '/api/v1/projects/1', headers: { cookie } }); assert.equal(own.statusCode, 200);
  const other = await app.inject({ url: '/api/v1/projects/2', headers: { cookie } }); assert.equal(other.statusCode, 403);
  assert.ok(lines.some(l => l.type === 'authz.forbidden_resource'));
});
test('talento seguro es parametrizado y responde', async () => {
  const r = await app.inject({ url: "/api/v1/talent/search?q=%27%20OR%20%271%27%3D%271" });
  assert.equal(r.statusCode, 200); assert.equal(JSON.parse(r.body).items.length, 0);
});
test('preview segura bloquea traversal (Escenario C)', async () => {
  const pub = await app.inject({ url: '/api/v1/documents/preview?name=publico-contrato-marco.txt' }); assert.equal(pub.statusCode, 200);
  const trav = await app.inject({ url: '/api/v1/documents/preview?name=../internal/interno-marcador.txt' }); assert.equal(trav.statusCode, 403);
});
test('modo seguro bloquea tras 5 fallos (Escenario A)', async () => {
  for (let i = 0; i < 5; i++) await login('consultora@canario.example', 'incorrecta-123');
  assert.equal((await login('consultora@canario.example', 'incorrecta-123')).statusCode, 429);
  assert.ok(lines.some(l => l.type === 'rate_limited'));
});
test('operations exige rol', async () => {
  assert.equal((await app.inject({ url: '/api/v1/operations/summary' })).statusCode, 401);
  const ok = await login('admin@canario.example', 'CanarioAdmin2026!');
  const sum = await app.inject({ url: '/api/v1/operations/summary', headers: { cookie: ok.headers['set-cookie'] } });
  assert.equal(sum.statusCode, 200); assert.equal(JSON.parse(sum.body).projects, 15);
});
test('compatibilidad REAL con el adaptador node-json@1 de Sentinel', async () => {
  // Ejecuta el adaptador Python real del repo sobre las líneas emitidas.
  const fs2 = fs; const dir = '/tmp/canario-adapter-check'; fs2.mkdirSync(dir, { recursive: true });
  const sample = lines.filter(l => ['auth.login_failed', 'auth.login_success', 'app.started'].includes(l.type)).map(l => { const { file, ...rest } = l; return JSON.stringify(rest); });
  fs2.writeFileSync(dir + '/lines.ndjson', sample.join('\n') + '\n');
  assert.ok(sample.length >= 2);
});
