import { loadConfig } from './config/config.js';
import { buildApp } from './app.js';
import { MemoryRepo, MysqlRepo } from './db/repo.js';
import { seedRepo } from './seed-apply.js';
const config = loadConfig();
let repo;
if (process.env.CANARIA_DB_DISABLED === '1') {
  // SOLO desarrollo/pruebas locales sin MySQL: los datos no persisten.
  process.stderr.write('canario-api: AVISO CANARIA_DB_DISABLED=1 — repositorio en memoria, SIN persistencia real.\n');
  repo = new MemoryRepo(); await seedRepo(repo, { demoPassword: process.env.CANARIA_DEMO_PASSWORD || 'CanarioDemo2026!', adminPassword: process.env.CANARIA_ADMIN_PASSWORD || 'CanarioAdmin2026!' });
} else {
  repo = await MysqlRepo.connect(config.db);
}
const app = await buildApp({ config, repo });
await app.listen({ port: config.port, host: config.host });
process.stderr.write(`canario-api escuchando en ${config.host}:${config.port} (modo ${config.labMode})\n`);
