import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config/config.js';
import { MemoryRepo } from '../src/db/repo.js';
import { seedRepo } from '../src/seed-apply.js';
import { createLogger } from '../src/logging/logger.js';
const lines = []; const logger = createLogger({ sink: (f, l) => lines.push(JSON.parse(l)) });
test('config: vulnerable sin aislamiento se niega a arrancar', () => {
  assert.throws(() => loadConfig({ CANARIA_LAB_MODE: 'vulnerable' }), /CANARIA_LAB_ISOLATED/);
});
let app; const repo = new MemoryRepo();
before(async () => {
  const config = loadConfig({ CANARIA_LAB_MODE: 'vulnerable', CANARIA_LAB_ISOLATED: '1', CANARIA_LAB_ALLOWED_CIDR: '127.0.0.0/8' });
  await seedRepo(repo, {}); app = await buildApp({ config, repo, logger });
});
after(async () => { await app.close(); });
test('Escenario A: la cuenta de laboratorio no se bloquea y el éxito correlaciona', async () => {
  for (let i = 0; i < 6; i++) { const r = await app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { email: 'lab.victima@canario.example', password: 'x' }, remoteAddress: '127.0.0.1' }); assert.equal(r.statusCode, 401); }
  const ok = await app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { email: 'lab.victima@canario.example', password: 'CanarioDemo2026!' }, remoteAddress: '127.0.0.1' });
  assert.equal(ok.statusCode, 200);
  assert.equal(lines.filter(l => l.type === 'auth.login_failed' && l.user === 'lab.victima@canario.example').length, 6);
  assert.equal(lines.filter(l => l.type === 'auth.login_success').length, 1);
});
test('Escenario C: traversal de laboratorio lee SOLO el árbol ficticio', async () => {
  const r = await app.inject({ url: '/api/v1/documents/preview?name=../internal/interno-marcador.txt', remoteAddress: '127.0.0.1' });
  assert.equal(r.statusCode, 200); assert.ok(r.body.includes('CANARIO-INTERNO-7F3A9'));
  const out = await app.inject({ url: '/api/v1/documents/preview?name=../../../../etc/passwd', remoteAddress: '127.0.0.1' });
  assert.equal(out.statusCode, 403);
});
test('Escenario F: ráfaga acotada de 503', async () => {
  const arm = await app.inject({ method: 'POST', url: '/api/v1/lab/error-burst', payload: { count: 3 }, remoteAddress: '127.0.0.1' }); assert.equal(arm.statusCode, 200);
  for (let i = 0; i < 3; i++) assert.equal((await app.inject({ url: '/api/v1/dependency/status', remoteAddress: '127.0.0.1' })).statusCode, 503);
  assert.equal((await app.inject({ url: '/api/v1/dependency/status', remoteAddress: '127.0.0.1' })).statusCode, 200);
  assert.equal(lines.filter(l => l.type === 'dependency.error').length, 3);
});
