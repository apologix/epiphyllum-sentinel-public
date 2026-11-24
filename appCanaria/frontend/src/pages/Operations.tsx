import React, { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { Badge, Loading, ErrorBox, Logo, useFetch } from '../components/ui';
import { api } from '../api';

const LINKS = [['/operations', 'Resumen'], ['/operations/clientes', 'Clientes'], ['/operations/proyectos', 'Proyectos'], ['/operations/leads', 'Leads'], ['/operations/solicitudes', 'Solicitudes de propuesta'], ['/operations/candidaturas', 'Candidaturas'], ['/operations/colaboradores', 'Colaboradores'], ['/operations/tickets', 'Tickets'], ['/operations/facturas', 'Facturas']];
export function OperationsLayout() {
  return (<div className="shell"><aside className="side"><Logo size={28} /><p className="muted small" style={{ margin: '14px 0' }}>Canario Operations · personal interno</p>
    <nav aria-label="Operaciones">{LINKS.map(([to, label]) => <NavLink key={to} to={to} end={to === '/operations'}>{label}</NavLink>)}</nav>
    <NavLink to="/portal">← Volver al portal</NavLink></aside>
    <div className="main"><div className="topbar"><strong>Canario Operations</strong><span className="muted small">Todo lo que entra por la web pública aparece aquí, desde la API.</span></div><Outlet /></div></div>);
}
export function OpsSummary() {
  const { data, loading, error } = useFetch<any>('/operations/summary');
  if (loading) return <Loading />; if (error) return <ErrorBox message={error} />;
  const cards = [['Clientes', data.clients], ['Proyectos', data.projects], ['Leads de contacto', data.leads], ['Solicitudes de propuesta', data.quotes], ['Candidaturas', data.applications], ['Colaboradores', data.consultants], ['Tickets abiertos', data.tickets_open], ['Facturas', data.invoices]];
  return (<><h2>Resumen de operaciones</h2><div className="grid c3" style={{ marginTop: 18 }}>{cards.map(([label, v]: any) => (<div className="card" key={label}><span className="muted small">{label}</span><div className="kpi">{v}</div></div>))}</div></>);
}
export function OpsTable({ title, path, columns, patchable }: { title: string; path: string; columns: [string, string][]; patchable?: boolean }) {
  const [pageN, setPageN] = useState(1); const [tick, setTick] = useState(0);
  const { data, loading, error } = useFetch<any>(`/operations/${path}?page=${pageN}&pageSize=12`, [pageN, tick]);
  if (loading) return <Loading />; if (error) return <ErrorBox message={error} />;
  const change = async (id: number, status: string) => { await api(`/operations/${path}/${id}`, { method: 'PATCH', body: { status } }); setTick(tick + 1); };
  return (<><h2>{title}</h2><div className="tablewrap" style={{ marginTop: 16 }}><table><thead><tr>{columns.map(([k, label]) => <th key={k}>{label}</th>)}{patchable && <th>Actualizar estado</th>}</tr></thead>
    <tbody>{data.items.map((r: any) => (<tr key={r.id}>{columns.map(([k]) => <td key={k}>{k === 'status' ? <Badge outline>{String(r[k] ?? '')}</Badge> : String(r[k] ?? '—').slice(0, 90)}</td>)}{patchable && (<td><select className="input" style={{ width: 150 }} value={r.status} onChange={e => change(r.id, e.target.value)} aria-label="Cambiar estado">{['nuevo', 'nueva', 'en revisión', 'contactada', 'recibida', 'en curso', 'abierto', 'resuelto', 'cerrado', 'activo', 'completado'].map(s => <option key={s}>{s}</option>)}</select></td>)}</tr>))}</tbody></table></div>
    <p className="muted small" style={{ marginTop: 12 }}>{data.total} registros · página {pageN}</p>
    <div style={{ display: 'flex', gap: 10 }}><button className="btn ghost small" disabled={pageN <= 1} onClick={() => setPageN(pageN - 1)}>Anterior</button><button className="btn ghost small" disabled={pageN * 12 >= data.total} onClick={() => setPageN(pageN + 1)}>Siguiente</button></div></>);
}
export const OpsClients = () => <OpsTable title="Clientes" path="clients" columns={[['name', 'Nombre'], ['industry', 'Industria'], ['country', 'País'], ['size', 'Tamaño']]} />;
export const OpsProjects = () => <OpsTable title="Proyectos" path="projects" columns={[['name', 'Nombre'], ['status', 'Estado'], ['manager', 'Responsable'], ['progress', 'Progreso %']]} patchable />;
export const OpsLeads = () => <OpsTable title="Leads de contacto" path="leads" columns={[['request_code', 'Código'], ['name', 'Nombre'], ['email', 'Correo'], ['subject', 'Asunto'], ['status', 'Estado']]} patchable />;
export const OpsQuotes = () => <OpsTable title="Solicitudes de propuesta" path="quotes" columns={[['request_code', 'Código'], ['company', 'Empresa'], ['service_slug', 'Servicio'], ['priority', 'Prioridad'], ['status', 'Estado']]} patchable />;
export const OpsApplications = () => <OpsTable title="Candidaturas" path="applications" columns={[['name', 'Nombre'], ['last_name', 'Apellidos'], ['email', 'Correo'], ['status', 'Estado']]} patchable />;
export const OpsConsultants = () => <OpsTable title="Colaboradores" path="consultants" columns={[['name', 'Nombre'], ['specialty', 'Especialidad'], ['years', 'Años'], ['availability', 'Disponibilidad']]} />;
export const OpsTickets = () => <OpsTable title="Tickets" path="tickets" columns={[['subject', 'Asunto'], ['category', 'Categoría'], ['priority', 'Prioridad'], ['status', 'Estado']]} patchable />;
export const OpsInvoices = () => <OpsTable title="Facturas" path="invoices" columns={[['number', 'Número'], ['concept', 'Concepto'], ['amount', 'Importe'], ['status', 'Estado']]} />;
