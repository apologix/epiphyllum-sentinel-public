import { loadConfig } from '../config/config.js';
import { MysqlRepo } from './repo.js'; import { seedRepo } from '../seed-apply.js';
const repo = await MysqlRepo.connect(loadConfig().db);
const r = await seedRepo(repo, { demoPassword: process.env.CANARIA_DEMO_PASSWORD || 'CanarioDemo2026!', adminPassword: process.env.CANARIA_ADMIN_PASSWORD || 'CanarioAdmin2026!' });
process.stderr.write(`seed: ${JSON.stringify(r)}\n`); await repo.close();
