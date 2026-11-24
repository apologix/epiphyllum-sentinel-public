/** Ejecuta backend/migrations/*.sql en orden contra MySQL. */
import fs from 'node:fs'; import path from 'node:path'; import mysql from 'mysql2/promise';
import { loadConfig } from '../config/config.js';
const cfg = loadConfig().db;
const conn = await mysql.createConnection({ host: cfg.host, port: cfg.port, user: cfg.user, password: cfg.password, multipleStatements: true });
await conn.query(`CREATE DATABASE IF NOT EXISTS \`${cfg.database}\``); await conn.changeUser({ database: cfg.database });
const dir = new URL('../../migrations/', import.meta.url).pathname;
for (const f of fs.readdirSync(dir).filter(x => x.endsWith('.sql')).sort()) { process.stderr.write(`migrate: ${f}\n`); await conn.query(fs.readFileSync(path.join(dir, f), 'utf8')); }
await conn.end(); process.stderr.write('migrate: ok\n');
