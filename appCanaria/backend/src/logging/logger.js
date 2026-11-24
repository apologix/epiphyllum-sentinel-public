/**
 * logger.js — Productor NDJSON compatible con el adaptador `node-json@1`
 * de Epiphyllum Sentinel (mcp/adapters/nodejs.py).
 *
 * CONTRATO REAL (verificado contra el código, planning/MCP-EVENT-CONTRACT.md
 * «Contrato del productor Node.js»): una línea = un objeto JSON con SOLO
 * estas claves: schema_version, timestamp, type, level, request_id, user,
 * src_ip, method, route, status, duration_ms, error_code, operation,
 * resource_id, organization, message. Cualquier clave extra hace que el
 * adaptador descarte la línea como evento (queda solo como texto).
 * `type` debe ser de la lista cerrada:
 *   auth.login_failed, auth.login_success,
 *   app.error, dependency.error, db.error,
 *   app.started, http.request, http.response, db.operation,
 *   validation.error, input.rejected, session.created, session.ended,
 *   authz.denied, authz.forbidden_resource, rate_limited,
 *   auth.anomaly, authz.anomaly
 * timestamp RFC 3339 CON zona. Sin contraseñas, tokens ni cookies, jamás.
 *
 * Los nombres de negocio del Prompt Maestro de Canario (p. ej.
 * `auth.login.failed`) NO existen en el contrato: aquí se traducen a los
 * tipos reales de arriba. Ver docs/08-OBSERVABILIDAD.md.
 */
import fs from 'node:fs';
import path from 'node:path';

export const ALLOWED_KEYS = new Set([
  'schema_version', 'timestamp', 'type', 'level', 'request_id', 'user',
  'src_ip', 'method', 'route', 'status', 'duration_ms', 'error_code',
  'operation', 'resource_id', 'organization', 'message',
]);
export const ALLOWED_TYPES = new Set([
  'auth.login_failed', 'auth.login_success',
  'app.error', 'dependency.error', 'db.error',
  'app.started', 'http.request', 'http.response', 'db.operation',
  'validation.error', 'input.rejected', 'session.created', 'session.ended',
  'authz.denied', 'authz.forbidden_resource', 'rate_limited',
  'auth.anomaly', 'authz.anomaly',
]);
const LEVELS = new Set(['info', 'warning', 'error']);
const SECURITY_TYPES = new Set([
  'auth.login_failed', 'auth.login_success', 'authz.denied',
  'authz.forbidden_resource', 'rate_limited', 'auth.anomaly',
  'authz.anomaly', 'input.rejected', 'session.created', 'session.ended',
]);

function clean(fields) {
  const out = {};
  for (const [k, v] of Object.entries(fields || {})) {
    if (!ALLOWED_KEYS.has(k) || v === undefined || v === null) continue;
    if (k === 'request_id' || k === 'error_code' || k === 'operation') {
      if (typeof v !== 'string' || v.length === 0 || v.length > (k === 'request_id' ? 64 : 32)) continue;
    }
    if (k === 'user' && (typeof v !== 'string' || v.length === 0 || v.length > 64)) continue;
    if (k === 'message' && typeof v === 'string') out[k] = v.slice(0, 300);
    else out[k] = v;
  }
  return out;
}

export function createLogger({ logDir, appFile = 'app.log', securityFile = 'security.log', sink = null } = {}) {
  const write = sink || ((file, line) => {
    try { fs.appendFileSync(path.join(logDir, file), line, 'utf8'); }
    catch (err) { process.stderr.write(`canario-api: no se pudo escribir ${file}: ${err.message}\n`); }
  });
  if (!sink && logDir) fs.mkdirSync(logDir, { recursive: true });

  function emit(type, fields = {}) {
    if (!ALLOWED_TYPES.has(type)) {
      process.stderr.write(`canario-api: tipo de log fuera de contrato, omitido: ${type}\n`);
      return null;
    }
    const entry = {
      schema_version: 1,
      timestamp: new Date().toISOString(),
      type,
      ...clean(fields),
    };
    if (entry.level !== undefined && !LEVELS.has(entry.level)) delete entry.level;
    const line = JSON.stringify(entry) + '\n';
    if (Buffer.byteLength(line, 'utf8') > 16 * 1024) return null; // límite MCP por línea
    write(SECURITY_TYPES.has(type) ? securityFile : appFile, line);
    return entry;
  }
  return { emit };
}
