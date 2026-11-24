/** Capa de repositorio. Dos implementaciones con la MISMA interfaz:
 * - MemoryRepo: pruebas y desarrollo sin MySQL (los datos NO persisten;
 *   jamás se presenta como persistencia real).
 * - MysqlRepo: producción en la VM (mysql2, consultas parametrizadas).
 * La interfaz es deliberadamente simple: colecciones con filas-objeto. */
export const TABLES = {
  organizations: 'organizations', users: 'users', sessions: 'sessions',
  services: 'services', industries: 'industries', case_studies: 'case_studies',
  jobs: 'jobs', job_applications: 'job_applications', contact_leads: 'contact_leads',
  quote_requests: 'quote_requests', projects: 'projects', project_members: 'project_members',
  project_milestones: 'project_milestones', consultants: 'consultants',
  tickets: 'tickets', ticket_comments: 'ticket_comments', documents: 'documents',
  invoices: 'invoices', activities: 'activities', password_resets: 'password_resets',
  talent: 'talent_directory',
};
export class MemoryRepo {
  constructor() { this.data = {}; this.seq = {}; for (const k of Object.keys(TABLES)) { this.data[k] = []; this.seq[k] = 1; } }
  async insert(coll, row) { const r = { id: this.seq[coll]++, created_at: new Date().toISOString(), ...row }; this.data[coll].push(r); return r; }
  async list(coll, filter = {}) { return this.data[coll].filter(r => Object.entries(filter).every(([k, v]) => r[k] === v)); }
  async get(coll, id) { return this.data[coll].find(r => r.id === Number(id)) || null; }
  async findOne(coll, filter) { const l = await this.list(coll, filter); return l[0] || null; }
  async update(coll, id, patch) { const r = await this.get(coll, id); if (!r) return null; Object.assign(r, patch); return r; }
  async remove(coll, id) { const i = this.data[coll].findIndex(r => r.id === Number(id)); if (i >= 0) this.data[coll].splice(i, 1); }
  async searchTalentSafe({ q = '', specialty = '' }) {
    return this.data.talent.filter(t => (!q || t.name.toLowerCase().includes(q.toLowerCase())) && (!specialty || t.specialty === specialty));
  }
  async ping() { return true; }
  async close() {}
}
const snake = s => s.replace(/[A-Z]/g, c => '_' + c.toLowerCase());
const camel = s => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
const isoToMysql = v => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(v)) ? v.replace('T', ' ').replace(/(\.\d+)?Z$/, '') : v;
function toRow(obj) { const o = {}; for (const [k, v] of Object.entries(obj)) o[snake(k)] = isoToMysql(v); return o; }
function fromRow(row) { return row || null; } // Las filas ya vienen en snake_case de MySQL, que es el contrato que usa toda la app (igual que MemoryRepo).
export class MysqlRepo {
  constructor(pool, labPool = null) { this.pool = pool; this.labPool = labPool; }
  static async connect(cfg) {
    const mysql = (await import('mysql2/promise')).default;
    const pool = mysql.createPool({ host: cfg.host, port: cfg.port, database: cfg.database, user: cfg.user, password: cfg.password, waitForConnections: true, connectionLimit: 10, namedPlaceholders: false });
    let labPool = null;
    try { labPool = mysql.createPool({ host: cfg.host, port: cfg.port, database: cfg.database, user: cfg.labUser, password: cfg.labPassword, connectionLimit: 2 }); } catch { labPool = null; }
    return new MysqlRepo(pool, labPool);
  }
  async insert(coll, row) {
    const r = toRow(row); const cols = Object.keys(r);
    const [res] = await this.pool.execute(`INSERT INTO \`${TABLES[coll]}\` (${cols.map(c => '`' + c + '`').join(',')}) VALUES (${cols.map(() => '?').join(',')})`, cols.map(c => r[c]));
    return this.get(coll, res.insertId);
  }
  async list(coll, filter = {}) {
    const f = toRow(filter); const keys = Object.keys(f);
    const sql = `SELECT * FROM \`${TABLES[coll]}\`` + (keys.length ? ` WHERE ${keys.map(k => '`' + k + '` = ?').join(' AND ')}` : '') + ' ORDER BY id';
    const [rows] = await this.pool.execute(sql, keys.map(k => f[k]));
    return rows.map(fromRow);
  }
  async get(coll, id) { const [rows] = await this.pool.execute(`SELECT * FROM \`${TABLES[coll]}\` WHERE id = ?`, [Number(id)]); return fromRow(rows[0]); }
  async findOne(coll, filter) { const l = await this.list(coll, filter); return l[0] || null; }
  async update(coll, id, patch) {
    const p = toRow(patch); const keys = Object.keys(p); if (!keys.length) return this.get(coll, id);
    await this.pool.execute(`UPDATE \`${TABLES[coll]}\` SET ${keys.map(k => '`' + k + '` = ?').join(',')} WHERE id = ?`, [...keys.map(k => p[k]), Number(id)]);
    return this.get(coll, id);
  }
  async remove(coll, id) { await this.pool.execute(`DELETE FROM \`${TABLES[coll]}\` WHERE id = ?`, [Number(id)]); }
  async searchTalentSafe({ q = '', specialty = '' }) {
    const [rows] = await this.pool.execute('SELECT * FROM `talent_directory` WHERE (? = \'\' OR name LIKE CONCAT(\'%\', ?, \'%\')) AND (? = \'\' OR specialty = ?) ORDER BY id', [q, q, specialty, specialty]);
    return rows.map(fromRow);
  }
  /** SOLO laboratorio, usuario MySQL de solo lectura canario_lab_ro sobre la
   * vista talent_public. La concatenación es la vulnerabilidad deliberada
   * del Escenario B; ver security-lab y docs/11. Nunca usar fuera de ahí. */
  async searchTalentVulnerable(q) {
    if (!this.labPool) throw new Error('lab pool no disponible');
    const sql = `SELECT * FROM talent_public WHERE name LIKE '%${q}%' ORDER BY id`;
    const [rows] = await this.labPool.query(sql);
    return rows;
  }
  async ping() { await this.pool.query('SELECT 1'); return true; }
  async close() { await this.pool.end(); if (this.labPool) await this.labPool.end(); }
}
