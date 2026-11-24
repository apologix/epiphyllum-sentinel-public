/** Aplica el dataset ficticio a cualquier Repo. Las contraseñas demo se
 * reciben por parámetro (en producción salen de env, fuera de Git). */
import { SERVICES, INDUSTRIES, CASE_STUDIES, ORGANIZATIONS, JOBS, buildConsultants, buildProjects } from './db/seed-data.js';
import { hashPassword } from './security.js';
export async function seedRepo(repo, { demoPassword = 'CanarioDemo2026!', adminPassword = 'CanarioAdmin2026!' } = {}) {
  if ((await repo.list('services')).length) return { seeded: false };
  for (const s of SERVICES) await repo.insert('services', s);
  for (const s of INDUSTRIES) await repo.insert('industries', s);
  for (const s of CASE_STUDIES) await repo.insert('case_studies', s);
  for (const o of ORGANIZATIONS) await repo.insert('organizations', o);
  for (const j of JOBS) await repo.insert('jobs', j);
  const consultants = buildConsultants();
  for (const c of consultants) { await repo.insert('consultants', c); await repo.insert('talent', { name: c.name, specialty: c.specialty, years: c.years, availability: c.availability, skills: c.skills }); }
  const projects = buildProjects(consultants);
  for (const p of projects) await repo.insert('projects', p);
  for (const p of projects) {
    await repo.insert('project_members', { project_id: p.id, consultant_id: ((p.id * 3) % 54) + 1, role_in_project: 'Asignado' });
    await repo.insert('project_milestones', { project_id: p.id, title: 'Arranque y descubrimiento', due_date: p.start_date, done: 1 });
    await repo.insert('project_milestones', { project_id: p.id, title: 'Entrega principal', due_date: p.target_date, done: 0 });
  }
  const users = [
    { name: 'Admin', last_name: 'Canario', email: 'admin@canario.example', role: 'admin', organization_id: null, password: adminPassword },
    { name: 'Olga', last_name: 'Operaciones', email: 'operaciones@canario.example', role: 'operations', organization_id: null, password: demoPassword },
    { name: 'Cliente', last_name: 'Nova', email: 'cliente@novapagos.example', role: 'client', organization_id: 1, password: demoPassword },
    { name: 'Cliente', last_name: 'Alba', email: 'cliente@clinicaalba.example', role: 'client', organization_id: 2, password: demoPassword },
    { name: 'María', last_name: 'Solano', email: 'consultora@canario.example', role: 'consultant', organization_id: null, password: demoPassword },
    // Cuenta ficticia autorizada para el Escenario A (fuerza bruta acotada):
    { name: 'Lab', last_name: 'Victima', email: 'lab.victima@canario.example', role: 'client', organization_id: 3, password: demoPassword },
  ];
  for (const u of users) { const { password, ...rest } = u; await repo.insert('users', { ...rest, password_hash: hashPassword(password) }); }
  for (let i = 0; i < 20; i++) await repo.insert('tickets', { organization_id: (i % 6) + 1, user_id: 3, subject: ['Acceso a reportes', 'Error al exportar', 'Solicitud de capacitación', 'Cambio de responsable'][i % 4], category: ['Soporte', 'Acceso', 'Operación'][i % 3], priority: ['alta', 'media', 'baja'][i % 3], description: 'Ticket ficticio de demostración.', status: ['abierto', 'en curso', 'resuelto'][i % 3], assignee: 'Operaciones Canario' });
  for (let i = 0; i < 15; i++) await repo.insert('invoices', { organization_id: (i % 6) + 1, number: `FAC-2026-${String(100 + i)}`, concept: 'Servicios profesionales mensuales (ficticio)', amount: 1200 + i * 175, currency: 'USD', status: ['pagada', 'pendiente', 'vencida'][i % 3], issued_date: '2026-10-01' });
  const docs = [['Contrato marco Nova (ficticio)', 'contrato', 1], ['Propuesta comercial Alba (ficticia)', 'propuesta', 2], ['Reporte mensual de operación', 'reporte', 1], ['Acuerdo de confidencialidad (ficticio)', 'acuerdo', 3], ['Entregable fase 1', 'entregable', 1]];
  for (const [title, type, org] of docs) await repo.insert('documents', { organization_id: org, title, type, file_name: 'publico-contrato-marco.txt', size_bytes: 512 });
  for (let i = 0; i < 25; i++) await repo.insert('quote_requests', { company: ORGANIZATIONS[i % 6].name, industry: 'tecnologia', country: 'Costa Rica', size: '11-50', contact_name: 'Contacto Ficticio', email: `contacto${i}@empresa${i}.example`, service_slug: SERVICES[i % 6].slug, problem: 'Necesidad ficticia de demostración.', professionals: 2, technologies: 'Node.js', modality: 'Remoto', start_date: '2026-12-01', duration: '6 meses', budget: '15000', priority: 'media', comments: '', status: ['nueva', 'en revisión', 'contactada'][i % 3], request_code: `PROP-2026-${String(1000 + i)}` });
  return { seeded: true };
}
