/**
 * app.js — Outsourcing Canario API (Fastify, monolito modular).
 * Segura por defecto. Los escenarios vulnerables viven SOLO tras
 * CANARIA_LAB_MODE=vulnerable + CANARIA_LAB_ISOLATED=1 + IP en
 * CANARIA_LAB_ALLOWED_CIDR (ver config.js y docs/11).
 * Logging: SOLO tipos/claves del contrato node-json@1 (logging/logger.js).
 */
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import fs from 'node:fs';
import path from 'node:path';
import { createLogger } from './logging/logger.js';
import { hashPassword, verifyPassword, newToken, newRequestId, ipInCidr, isPrivateIp } from './security.js';

const LAB_LAB_ACCOUNTS = new Set(['lab.victima@canario.example']);
const page = (items, q) => { const p = Math.max(1, Number(q.page || 1)); const s = Math.min(100, Math.max(1, Number(q.pageSize || 20))); return { items: items.slice((p - 1) * s, p * s), total: items.length, page: p, pageSize: s }; };
const pub = u => u ? { id: u.id, name: u.name, last_name: u.last_name, email: u.email, role: u.role, organization_id: u.organization_id } : null;

export async function buildApp({ config, repo, logger }) {
  const log = logger || createLogger({ logDir: config.logDir });
  const app = Fastify({ logger: false, trustProxy: true });
  await app.register(cookie, { secret: config.sessionSecret });
  const loginState = new Map(); // email -> {failures, lockedUntil}

  app.addHook('onRequest', async (req, reply) => {
    const incoming = req.headers['x-request-id'];
    // Nginx (infra/nginx) SOBRESCRIBE X-Request-Id con $request_id, así que
    // detrás de Nginx el valor es confiable. Un cliente directo podría
    // inventarlo: la correlación es diagnóstica, nunca autorización.
    req.requestId = (typeof incoming === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(incoming)) ? incoming : newRequestId();
    reply.header('x-request-id', req.requestId);
    req.startedAt = Date.now();
  });
  app.addHook('onResponse', async (req, reply) => {
    log.emit('http.response', { request_id: req.requestId, method: req.method, route: (req.routeOptions && req.routeOptions.url) || req.url.split('?')[0], status: reply.statusCode, duration_ms: Date.now() - (req.startedAt || Date.now()), src_ip: req.ip });
  });
  const L = (type, req, fields = {}) => log.emit(type, { request_id: req.requestId, src_ip: req.ip, method: req.method, route: (req.routeOptions && req.routeOptions.url) || req.url.split('?')[0], ...fields });
  const fail = (reply, status, code, message) => reply.code(status).send({ error: { code, message }, request_id: reply.request?.requestId });

  async function currentUser(req) {
    const sid = req.cookies.canario_session;
    if (!sid) return null;
    const s = await repo.findOne('sessions', { token_hash: sid });
    if (!s || new Date(s.expires_at) < new Date()) return null;
    return repo.get('users', s.user_id);
  }
  async function requireAuth(req, reply) { const u = await currentUser(req); if (!u) { fail(reply, 401, 'unauthorized', 'Sesión requerida.'); return null; } req.user = u; return u; }
  async function requireRole(req, reply, roles) { const u = await requireAuth(req, reply); if (!u) return null; if (!roles.includes(u.role)) { L('authz.denied', req, { user: u.email, status: 403 }); fail(reply, 403, 'forbidden', 'Rol insuficiente.'); return null; } return u; }
  const labGate = req => config.labMode === 'vulnerable' && config.labIsolated && ipInCidr(req.ip, config.labAllowedCidr) && isPrivateIp(req.ip);
  async function activity(user, action, detail) { await repo.insert('activities', { user_id: user?.id || null, organization_id: user?.organization_id || null, action, detail }); }

  // ---------- salud ----------
  app.get('/api/v1/health/live', async () => ({ status: 'live', version: config.appVersion }));
  app.get('/api/v1/health/ready', async (req, reply) => { try { await repo.ping(); return { status: 'ready' }; } catch { L('dependency.error', req, { error_code: 'E_DB_CONN', status: 503 }); return reply.code(503).send({ status: 'not-ready' }); } });

  // ---------- público ----------
  app.get('/api/v1/services', async () => ({ items: await repo.list('services') }));
  app.get('/api/v1/services/:slug', async (req, reply) => { const s = await repo.findOne('services', { slug: req.params.slug }); return s || fail(reply, 404, 'not_found', 'Servicio no encontrado.'); });
  app.get('/api/v1/industries', async () => ({ items: await repo.list('industries') }));
  app.get('/api/v1/case-studies', async (req) => { let items = await repo.list('case_studies'); if (req.query.industry) items = items.filter(c => c.industry === req.query.industry); if (req.query.service) items = items.filter(c => c.service === req.query.service); return { items }; });
  app.get('/api/v1/case-studies/:slug', async (req, reply) => { const s = await repo.findOne('case_studies', { slug: req.params.slug }); return s || fail(reply, 404, 'not_found', 'Caso no encontrado.'); });
  app.get('/api/v1/jobs', async (req) => { let items = (await repo.list('jobs')).filter(j => j.status === 'abierta'); for (const k of ['area', 'modality', 'level', 'location']) if (req.query[k]) items = items.filter(j => j[k] === req.query[k]); if (req.query.q) items = items.filter(j => (j.title + j.tech).toLowerCase().includes(String(req.query.q).toLowerCase())); return { items }; });
  app.get('/api/v1/jobs/:id', async (req, reply) => { const j = await repo.get('jobs', req.params.id) || await repo.findOne('jobs', { slug: req.params.id }); return j || fail(reply, 404, 'not_found', 'Vacante no encontrada.'); });

  const need = (body, fields, req, reply) => { for (const f of fields) if (!body?.[f] || String(body[f]).trim() === '') { L('validation.error', req, { status: 400, message: `Falta el campo ${f}` }); fail(reply, 400, 'validation', `Falta el campo obligatorio: ${f}`); return false; } return true; };
  const emailOk = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || ''));

  app.post('/api/v1/contact', async (req, reply) => {
    const b = req.body || {}; if (!need(b, ['name', 'email', 'message'], req, reply)) return; if (!emailOk(b.email)) { L('validation.error', req, { status: 400 }); return fail(reply, 400, 'validation', 'Correo inválido.'); }
    // El mensaje es TEXTO NO CONFIABLE (Escenario E): se guarda como dato,
    // se registra delimitado en el log vía message (≤300, evidencia) y
    // NUNCA se interpreta como instrucción.
    const lead = await repo.insert('contact_leads', { name: b.name, email: b.email, phone: b.phone || '', company: b.company || '', department: b.department || '', subject: b.subject || 'Consulta desde la landing', message: String(b.message).slice(0, 2000), contact_preference: b.contact_preference || 'correo', status: 'nuevo', request_code: 'CON-' + Date.now().toString(36).toUpperCase() });
    L('http.request', req, { status: 201, operation: 'contact.create', message: `contacto ${lead.request_code}: ${String(b.message).slice(0, 120)}` });
    return reply.code(201).send({ id: lead.id, request_code: lead.request_code });
  });
  app.post('/api/v1/quotes', async (req, reply) => {
    const b = req.body || {}; if (!need(b, ['company', 'contact_name', 'email', 'service_slug'], req, reply)) return; if (!emailOk(b.email)) return fail(reply, 400, 'validation', 'Correo inválido.');
    const q = await repo.insert('quote_requests', { company: b.company, industry: b.industry || '', country: b.country || '', size: b.size || '', contact_name: b.contact_name, email: b.email, service_slug: b.service_slug, problem: b.problem || '', professionals: Number(b.professionals || 1), technologies: b.technologies || '', modality: b.modality || '', start_date: b.start_date || '', duration: b.duration || '', budget: b.budget || '', priority: b.priority || 'media', comments: b.comments || '', status: 'nueva', request_code: 'PROP-' + Date.now().toString(36).toUpperCase() });
    L('http.request', req, { status: 201, operation: 'quote.create' });
    return reply.code(201).send({ id: q.id, request_code: q.request_code });
  });
  app.post('/api/v1/applications', async (req, reply) => {
    const b = req.body || {}; if (!need(b, ['job_id', 'name', 'last_name', 'email'], req, reply)) return; if (!emailOk(b.email)) return fail(reply, 400, 'validation', 'Correo inválido.');
    const job = await repo.get('jobs', b.job_id); if (!job) return fail(reply, 404, 'not_found', 'Vacante no encontrada.');
    const a = await repo.insert('job_applications', { job_id: job.id, name: b.name, last_name: b.last_name, email: b.email, phone: b.phone || '', country: b.country || '', experience: b.experience || '', profile: b.profile || '', portfolio_url: b.portfolio_url || '', cover_letter: String(b.cover_letter || '').slice(0, 2000), cv_file_name: b.cv_file_name || '', status: 'recibida' });
    L('http.request', req, { status: 201, operation: 'application.create' });
    return reply.code(201).send({ id: a.id });
  });

  // ---------- talento (Escenario B) ----------
  app.get('/api/v1/talent/search', async (req, reply) => {
    const q = String(req.query.q || ''); const specialty = String(req.query.specialty || '');
    if (q.length > 80) { L('input.rejected', req, { status: 400, message: 'búsqueda demasiado larga' }); return fail(reply, 400, 'validation', 'Búsqueda demasiado larga.'); }
    if (labGate(req) && req.query.__lab === 'sqli' && typeof repo.searchTalentVulnerable === 'function') {
      // ESCENARIO B (solo laboratorio verificado): consulta NO parametrizada
      // con el usuario MySQL de SOLO LECTURA sobre la vista talent_public.
      try { const rows = await repo.searchTalentVulnerable(q); L('input.rejected', req, { status: 200, operation: 'talent.search', message: 'ruta vulnerable de laboratorio ejecutada' }); return { items: rows, lab: 'vulnerable' }; }
      catch (e) { L('db.error', req, { error_code: 'E_SQL', status: 500, message: String(e.message).slice(0, 200) }); return fail(reply, 500, 'db_error', 'Error de base de datos (evidencia en el log).'); }
    }
    const items = await repo.searchTalentSafe({ q, specialty });
    L('db.operation', req, { operation: 'select', status: 200 });
    return { items };
  });

  // ---------- auth ----------
  app.post('/api/v1/auth/register', async (req, reply) => {
    const b = req.body || {}; if (!need(b, ['name', 'last_name', 'email', 'password'], req, reply)) return;
    if (!emailOk(b.email)) return fail(reply, 400, 'validation', 'Correo inválido.');
    if (String(b.password).length < 10) return fail(reply, 400, 'validation', 'La contraseña debe tener al menos 10 caracteres.');
    if (await repo.findOne('users', { email: b.email })) return fail(reply, 409, 'conflict', 'Ya existe una cuenta con ese correo.');
    let org = null;
    if (b.company) org = await repo.insert('organizations', { name: b.company, industry: '', country: '', size: '' });
    const u = await repo.insert('users', { name: b.name, last_name: b.last_name, email: b.email, role: 'client', organization_id: org?.id || null, password_hash: hashPassword(b.password) });
    L('http.request', req, { status: 201, operation: 'auth.register', user: u.email });
    return reply.code(201).send({ user: pub(u) });
  });
  app.post('/api/v1/auth/login', async (req, reply) => {
    const b = req.body || {}; const email = String(b.email || ''); const password = String(b.password || '');
    const user = await repo.findOne('users', { email });
    const st = loginState.get(email) || { failures: 0, lockedUntil: 0 };
    const labAccount = labGate(req) && LAB_LAB_ACCOUNTS.has(email);
    if (!labAccount && st.lockedUntil > Date.now()) { L('rate_limited', req, { user: email, status: 429 }); return fail(reply, 429, 'rate_limited', 'Demasiados intentos. Esperá unos minutos.'); }
    if (!user || !verifyPassword(password, user.password_hash)) {
      st.failures++; if (!labAccount && st.failures >= config.loginMaxFailures) { st.lockedUntil = Date.now() + config.loginLockMinutes * 60000; st.failures = 0; }
      loginState.set(email, st);
      // user SIEMPRE presente (aunque la cuenta no exista usamos el correo
      // intentado) y src_ip: mínimos para que node-json@1 emita auth.failed.
      L('auth.login_failed', req, { user: email || 'desconocido', status: 401 });
      return fail(reply, 401, 'invalid_credentials', 'Correo o contraseña incorrectos.');
    }
    loginState.delete(email);
    const token = newToken();
    await repo.insert('sessions', { user_id: user.id, token_hash: token, expires_at: new Date(Date.now() + config.sessionTtlHours * 3600000).toISOString() });
    reply.setCookie('canario_session', token, { httpOnly: true, sameSite: 'lax', path: '/', maxAge: config.sessionTtlHours * 3600 });
    L('auth.login_success', req, { user: user.email, status: 200 });
    L('session.created', req, { user: user.email, status: 200 });
    await activity(user, 'auth.login', 'Inicio de sesión');
    return { user: pub(user) };
  });
  app.post('/api/v1/auth/logout', async (req, reply) => { const u = await currentUser(req); const sid = req.cookies.canario_session; if (sid) { const s = await repo.findOne('sessions', { token_hash: sid }); if (s) await repo.remove('sessions', s.id); } reply.clearCookie('canario_session', { path: '/' }); if (u) L('session.ended', req, { user: u.email, status: 200 }); return { ok: true }; });
  app.get('/api/v1/auth/me', async (req, reply) => { const u = await requireAuth(req, reply); return u ? { user: pub(u) } : undefined; });
  app.post('/api/v1/auth/forgot-password', async (req, reply) => {
    const email = String(req.body?.email || ''); const user = await repo.findOne('users', { email });
    if (user) { // El token NUNCA va en la respuesta: sale al outbox local del instructor.
      const token = newToken(); await repo.insert('password_resets', { user_id: user.id, token_hash: token, expires_at: new Date(Date.now() + 3600000).toISOString(), used: 0 });
      try { fs.mkdirSync(config.outboxDir, { recursive: true }); fs.writeFileSync(path.join(config.outboxDir, `reset-${user.id}-${Date.now()}.txt`), `Restablecimiento Canario (demo)\nCorreo: ${email}\nToken: ${token}\nVence en 1 hora.\n`); } catch { /* outbox no disponible: queda el registro en BD */ }
      L('http.request', req, { user: email, status: 202, operation: 'auth.forgot' });
    }
    return reply.code(202).send({ ok: true, message: 'Si la cuenta existe, el instructor del laboratorio puede entregar el enlace de restablecimiento.' });
  });
  app.post('/api/v1/auth/reset-password', async (req, reply) => {
    const { token, password } = req.body || {}; if (!token || String(password || '').length < 10) return fail(reply, 400, 'validation', 'Token o contraseña inválidos.');
    const r = await repo.findOne('password_resets', { token_hash: String(token) }); if (!r || r.used || new Date(r.expires_at) < new Date()) return fail(reply, 400, 'invalid_token', 'El enlace venció o ya fue usado.');
    await repo.update('users', r.user_id, { password_hash: hashPassword(password) }); await repo.update('password_resets', r.id, { used: 1 });
    L('http.request', req, { status: 200, operation: 'auth.reset' });
    return { ok: true };
  });

  // ---------- portal autenticado ----------
  const orgScope = u => (u.role === 'admin' || u.role === 'operations') ? null : u.organization_id;
  app.get('/api/v1/dashboard', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const scope = orgScope(u);
    const projects = (await repo.list('projects')).filter(p => scope === null || p.organization_id === scope);
    const tickets = (await repo.list('tickets')).filter(t => scope === null || t.organization_id === scope);
    const requests = (await repo.list('quote_requests'));
    const members = await repo.list('project_members');
    return { projects_active: projects.filter(p => p.status === 'activo').length, projects, collaborators: new Set(members.map(m => m.consultant_id)).size || (await repo.list('consultants')).length, requests_pending: requests.filter(r => r.status === 'nueva').length, tickets_open: tickets.filter(t => t.status === 'abierto').length, milestones: (await repo.list('project_milestones')).filter(m => !m.done).slice(0, 5), activity: (await repo.list('activities')).slice(-8).reverse() };
  });
  app.get('/api/v1/projects', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const scope = orgScope(u);
    let items = (await repo.list('projects')).filter(p => scope === null || p.organization_id === scope);
    if (req.query.status) items = items.filter(p => p.status === req.query.status);
    if (req.query.q) items = items.filter(p => p.name.toLowerCase().includes(String(req.query.q).toLowerCase()));
    return page(items, req.query);
  });
  app.get('/api/v1/projects/:id', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return;
    const p = await repo.get('projects', req.params.id); if (!p) return fail(reply, 404, 'not_found', 'Proyecto no encontrado.');
    const scope = orgScope(u);
    if (scope !== null && p.organization_id !== scope) {
      // ESCENARIO D (IDOR): en modo seguro se deniega; en laboratorio
      // verificado se permite la lectura cruzada y queda registrada.
      if (labGate(req)) { L('authz.anomaly', req, { user: u.email, status: 200, resource_id: String(p.id), organization: String(p.organization_id), message: 'lectura cruzada IDOR de laboratorio' }); return { ...p, lab: 'idor' }; }
      L('authz.forbidden_resource', req, { user: u.email, status: 403, resource_id: String(p.id), organization: String(p.organization_id) });
      return fail(reply, 403, 'forbidden', 'Este proyecto pertenece a otra organización.');
    }
    const members = await repo.list('project_members', { project_id: p.id });
    const consultants = await repo.list('consultants');
    return { ...p, team: members.map(m => consultants.find(c => c.id === m.consultant_id)).filter(Boolean), milestones: await repo.list('project_milestones', { project_id: p.id }), documents: (await repo.list('documents')).filter(d => d.organization_id === p.organization_id) };
  });
  app.get('/api/v1/team', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; return page(await repo.list('consultants'), req.query); });
  app.get('/api/v1/requests', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; return page(await repo.list('quote_requests'), req.query); });
  app.post('/api/v1/requests', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const b = req.body || {}; if (!need(b, ['service_slug', 'problem'], req, reply)) return;
    const org = u.organization_id ? await repo.get('organizations', u.organization_id) : null;
    const q = await repo.insert('quote_requests', { company: org?.name || 'Mi organización', industry: org?.industry || '', country: org?.country || '', size: org?.size || '', contact_name: u.name, email: u.email, service_slug: b.service_slug, problem: b.problem, professionals: Number(b.professionals || 1), technologies: b.technologies || '', modality: b.modality || '', start_date: b.start_date || '', duration: b.duration || '', budget: b.budget || '', priority: b.priority || 'media', comments: '', status: 'nueva', request_code: 'PROP-' + Date.now().toString(36).toUpperCase() });
    return reply.code(201).send(q);
  });
  app.get('/api/v1/documents', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const scope = orgScope(u); return page((await repo.list('documents')).filter(d => scope === null || d.organization_id === scope), req.query); });
  app.get('/api/v1/documents/:id', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const d = await repo.get('documents', req.params.id); if (!d) return fail(reply, 404, 'not_found', 'Documento no encontrado.'); const scope = orgScope(u); if (scope !== null && d.organization_id !== scope) { L('authz.forbidden_resource', req, { user: u.email, status: 403, resource_id: String(d.id) }); return fail(reply, 403, 'forbidden', 'Documento de otra organización.'); } return d; });

  // Escenario C: previsualización con sandbox de laboratorio.
  app.get('/api/v1/documents/preview', async (req, reply) => {
    const name = String(req.query.name || '');
    const base = path.resolve(config.labFilesDir);
    const pubDir = path.join(base, 'public');
    if (labGate(req)) {
      // Vulnerable: resuelve contra lab-files/ SIN confinar a public/ —
      // puede leer lab-files/internal/ (árbol ficticio), jamás fuera de
      // lab-files: el `..` se recorta al sandbox del laboratorio.
      const resolved = path.resolve(pubDir, name.replace(/^\/+/, ''));
      if (!resolved.startsWith(base)) { L('authz.anomaly', req, { status: 403, message: 'traversal fuera del sandbox bloqueado incluso en laboratorio' }); return fail(reply, 403, 'forbidden', 'Fuera del área de laboratorio.'); }
      try { const content = fs.readFileSync(resolved, 'utf8'); L('authz.anomaly', req, { status: 200, resource_id: name, message: `preview vulnerable resolvió ${resolved.slice(base.length)}` }); return reply.type('text/plain').send(content); }
      catch { return fail(reply, 404, 'not_found', 'Archivo no encontrado.'); }
    }
    const resolved = path.resolve(pubDir, '.' + path.sep + name.replace(/^\/+/, ''));
    if (!resolved.startsWith(pubDir)) { L('input.rejected', req, { status: 403, message: 'traversal bloqueado en modo seguro' }); return fail(reply, 403, 'forbidden', 'Ruta no permitida.'); }
    try { return reply.type('text/plain').send(fs.readFileSync(resolved, 'utf8')); } catch { return fail(reply, 404, 'not_found', 'Archivo no encontrado.'); }
  });

  app.get('/api/v1/tickets', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const scope = orgScope(u); return page((await repo.list('tickets')).filter(t => scope === null || t.organization_id === scope), req.query); });
  app.post('/api/v1/tickets', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const b = req.body || {}; if (!need(b, ['subject', 'description'], req, reply)) return;
    const t = await repo.insert('tickets', { organization_id: u.organization_id, user_id: u.id, subject: b.subject, category: b.category || 'Soporte', priority: b.priority || 'media', description: b.description, status: 'abierto', assignee: '' });
    L('http.request', req, { user: u.email, status: 201, operation: 'ticket.create' }); return reply.code(201).send(t); });
  app.get('/api/v1/tickets/:id', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const t = await repo.get('tickets', req.params.id); if (!t) return fail(reply, 404, 'not_found', 'Ticket no encontrado.'); const scope = orgScope(u); if (scope !== null && t.organization_id !== scope) return fail(reply, 403, 'forbidden', 'Ticket de otra organización.'); return { ...t, comments: await repo.list('ticket_comments', { ticket_id: t.id }) }; });
  app.post('/api/v1/tickets/:id/comments', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const t = await repo.get('tickets', req.params.id); if (!t) return fail(reply, 404, 'not_found', 'Ticket no encontrado.'); const c = await repo.insert('ticket_comments', { ticket_id: t.id, user_id: u.id, body: String(req.body?.body || '').slice(0, 2000) }); return reply.code(201).send(c); });
  app.get('/api/v1/invoices', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const scope = orgScope(u); return page((await repo.list('invoices')).filter(i => scope === null || i.organization_id === scope), req.query); });
  app.get('/api/v1/activity', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const scope = orgScope(u); return page((await repo.list('activities')).filter(a => scope === null || a.organization_id === scope || a.user_id === u.id).reverse(), req.query); });
  app.get('/api/v1/profile', async (req, reply) => { const u = await requireAuth(req, reply); return u ? { user: pub(u) } : undefined; });
  app.patch('/api/v1/profile', async (req, reply) => { const u = await requireAuth(req, reply); if (!u) return; const b = req.body || {}; const patch = {}; if (b.name) patch.name = b.name; if (b.last_name) patch.last_name = b.last_name; const updated = await repo.update('users', u.id, patch); return { user: pub(updated) }; });

  // Escenario F: ráfaga acotada de 503 (solo laboratorio verificado).
  let burstLeft = 0;
  app.post('/api/v1/lab/error-burst', async (req, reply) => { if (!labGate(req)) return fail(reply, 404, 'not_found', 'No disponible.'); burstLeft = Math.min(10, Number(req.body?.count || 5)); L('http.request', req, { status: 202, operation: 'lab.burst.arm', message: `ráfaga de ${burstLeft} errores armada por el instructor` }); return { armed: burstLeft }; });
  app.get('/api/v1/dependency/status', async (req, reply) => { if (burstLeft > 0) { burstLeft--; L('dependency.error', req, { error_code: 'E_UPSTREAM', status: 503, message: 'dependencia ficticia en ráfaga de laboratorio' }); return reply.code(503).send({ error: { code: 'upstream', message: 'Dependencia no disponible (ráfaga de laboratorio).' }, request_id: req.requestId }); } return { dependency: 'ok' }; });

  // ---------- operaciones (admin/operations) ----------
  const ops = async (req, reply) => requireRole(req, reply, ['admin', 'operations']);
  app.get('/api/v1/operations/summary', async (req, reply) => { const u = await ops(req, reply); if (!u) return; return { clients: (await repo.list('organizations')).length, projects: (await repo.list('projects')).length, leads: (await repo.list('contact_leads')).length, quotes: (await repo.list('quote_requests')).length, applications: (await repo.list('job_applications')).length, consultants: (await repo.list('consultants')).length, tickets_open: (await repo.list('tickets')).filter(t => t.status === 'abierto').length, invoices: (await repo.list('invoices')).length }; });
  const opsList = coll => async (req, reply) => { const u = await ops(req, reply); if (!u) return; return page(await repo.list(coll), req.query); };
  app.get('/api/v1/operations/clients', opsList('organizations'));
  app.get('/api/v1/operations/projects', opsList('projects'));
  app.get('/api/v1/operations/leads', opsList('contact_leads'));
  app.get('/api/v1/operations/quotes', opsList('quote_requests'));
  app.get('/api/v1/operations/applications', opsList('job_applications'));
  app.get('/api/v1/operations/consultants', opsList('consultants'));
  app.get('/api/v1/operations/tickets', opsList('tickets'));
  app.get('/api/v1/operations/invoices', opsList('invoices'));
  const opsPatch = coll => async (req, reply) => { const u = await ops(req, reply); if (!u) return; const allowed = {}; if (req.body?.status) allowed.status = String(req.body.status).slice(0, 40); const r = await repo.update(coll, req.params.id, allowed); return r || fail(reply, 404, 'not_found', 'Registro no encontrado.'); };
  app.patch('/api/v1/operations/leads/:id', opsPatch('contact_leads'));
  app.patch('/api/v1/operations/quotes/:id', opsPatch('quote_requests'));
  app.patch('/api/v1/operations/applications/:id', opsPatch('job_applications'));
  app.patch('/api/v1/operations/tickets/:id', opsPatch('tickets'));
  app.patch('/api/v1/operations/projects/:id', opsPatch('projects'));

  app.setErrorHandler((err, req, reply) => { L('app.error', req, { error_code: 'E_INTERNAL', status: 500, message: String(err.message).slice(0, 200) }); reply.code(500).send({ error: { code: 'internal', message: 'Error interno.' }, request_id: req.requestId }); });
  log.emit('app.started', { message: `canario-api ${config.appVersion} modo ${config.labMode} puerto ${config.port}` });
  return app;
}
