import React, { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useNavigate, useParams } from 'react-router-dom';
import { Button, Badge, Field, Loading, ErrorBox, Logo, useAuth, useFetch } from '../components/ui';
import { Input } from '../components/arc/input/input';
import { api, fmtDate } from '../api';

const LINKS = [['/portal', 'Resumen'], ['/portal/proyectos', 'Proyectos'], ['/portal/equipo', 'Equipo asignado'], ['/portal/solicitudes', 'Solicitudes'], ['/portal/documentos', 'Documentos'], ['/portal/tickets', 'Tickets'], ['/portal/facturacion', 'Facturación'], ['/portal/actividad', 'Actividad'], ['/portal/perfil', 'Perfil']];
export function PortalLayout() {
  const { user } = useAuth(); const navigate = useNavigate(); const [open, setOpen] = useState(false);
  const logout = async () => { await api('/auth/logout', { method: 'POST' }); navigate('/login'); };
  return (<div className="shell">
    <aside className={'side' + (open ? ' open' : '')}><Logo size={28} />
      <p className="muted small" style={{ margin: '14px 0 4px' }}>Canario Workspace</p>
      {user && <p className="small" style={{ margin: '0 0 14px' }}>{user.name} {user.last_name}<br /><span className="muted">{user.role}</span></p>}
      <nav aria-label="Portal">{LINKS.map(([to, label]) => <NavLink key={to} to={to} end={to === '/portal'} onClick={() => setOpen(false)}>{label}</NavLink>)}</nav>
      {(user?.role === 'admin' || user?.role === 'operations') && <NavLink to="/operations">Canario Operations</NavLink>}
      <button className="btn ghost small" style={{ marginTop: 16 }} onClick={logout}>Cerrar sesión</button>
    </aside>
    <div className="main">
      <div className="topbar"><button className="burger" style={{ display: 'inline-block' }} aria-label="Abrir navegación" onClick={() => setOpen(!open)}>☰</button><strong>Canario Workspace</strong><span className="muted small">Portal privado · datos servidos por la API</span></div>
      <Outlet />
    </div></div>);
}
export function Dashboard() {
  const { data, loading, error } = useFetch<any>('/dashboard');
  if (loading) return <Loading />; if (error) return <ErrorBox message={error} />;
  return (<><h2>Resumen</h2>
    <div className="grid c3" style={{ margin: '18px 0' }}>
      <div className="card"><span className="muted small">Proyectos activos</span><div className="kpi">{data.projects_active}</div></div>
      <div className="card"><span className="muted small">Colaboradores asignados</span><div className="kpi">{data.collaborators}</div></div>
      <div className="card"><span className="muted small">Tickets abiertos</span><div className="kpi">{data.tickets_open}</div></div>
    </div>
    <div className="grid c2">
      <div className="card"><h3>Estado de proyectos</h3>{data.projects.slice(0, 5).map((p: any) => (<div key={p.id} style={{ marginBottom: 12 }}><div style={{ display: 'flex', justifyContent: 'space-between' }}><Link to={`/portal/proyectos/${p.id}`}>{p.name}</Link><span className="muted small">{p.progress}%</span></div><div className="progress"><i style={{ width: p.progress + '%' }} /></div></div>))}</div>
      <div className="card"><h3>Próximos hitos</h3>{data.milestones.map((m: any) => <p key={m.id} className="muted small" style={{ margin: '6px 0' }}>{m.title} · vence {fmtDate(m.due_date)}</p>)}<h3 style={{ marginTop: 18 }}>Actividad reciente</h3>{data.activity.length === 0 && <p className="muted small">Todavía no hay actividad registrada en tu cuenta.</p>}{data.activity.map((a: any) => <p key={a.id} className="muted small" style={{ margin: '6px 0' }}>{a.action} — {a.detail}</p>)}</div>
    </div></>);
}
function Pager({ page, setPage, total, pageSize }: any) { const pages = Math.max(1, Math.ceil(total / pageSize)); return (<div style={{ display: 'flex', gap: 10, marginTop: 14, alignItems: 'center' }}><Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage(page - 1)}>Anterior</Button><span className="muted small">Página {page} de {pages} · {total} registros</span><Button size="sm" variant="secondary" disabled={page >= pages} onClick={() => setPage(page + 1)}>Siguiente</Button></div>); }
export function ProjectsPage() {
  const [q, setQ] = useState(''); const [status, setStatus] = useState(''); const [pageN, setPageN] = useState(1);
  const { data, loading, error } = useFetch<any>(`/projects?page=${pageN}&pageSize=8&q=${encodeURIComponent(q)}&status=${status}`, [pageN, q, status]);
  if (loading) return <Loading />; if (error) return <ErrorBox message={error} />;
  return (<><h2>Proyectos</h2><div style={{ display: 'flex', gap: 10, margin: '16px 0', flexWrap: 'wrap' }}><div style={{ flex: '1 1 220px' }}><Input value={q} onChange={e => { setQ(e.target.value); setPageN(1); }} placeholder="Buscar proyecto" aria-label="Buscar proyecto" /></div><select className="input" style={{ width: 180 }} value={status} onChange={e => { setStatus(e.target.value); setPageN(1); }} aria-label="Estado"><option value="">Todos los estados</option>{['activo', 'en riesgo', 'completado'].map(s => <option key={s}>{s}</option>)}</select></div>
    <div className="tablewrap"><table><thead><tr><th>Nombre</th><th>Estado</th><th>Responsable</th><th>Inicio</th><th>Objetivo</th><th>Progreso</th><th>Prioridad</th></tr></thead><tbody>{data.items.map((p: any) => (<tr key={p.id}><td><Link to={`/portal/proyectos/${p.id}`} style={{ color: 'var(--accent)' }}>{p.name}</Link></td><td><Badge tone={p.status === 'en riesgo' ? 'warning' : p.status === 'completado' ? 'success' : 'info'}>{p.status}</Badge></td><td>{p.manager}</td><td>{fmtDate(p.start_date)}</td><td>{fmtDate(p.target_date)}</td><td>{p.progress}%</td><td>{p.priority}</td></tr>))}</tbody></table></div>
    <Pager page={pageN} setPage={setPageN} total={data.total} pageSize={data.pageSize} /></>);
}
export function ProjectDetail() {
  const { id } = useParams(); const { data: p, loading, error } = useFetch<any>(`/projects/${id}`, [id]);
  if (loading) return <Loading />; if (error) return <ErrorBox message={error} />; if (!p) return null;
  return (<><Link to="/portal/proyectos" className="muted small">← Proyectos</Link><h2 style={{ marginTop: 10 }}>{p.name}</h2><p className="muted">{p.description}</p>
    <div className="grid c3" style={{ margin: '18px 0' }}><div className="card"><span className="muted small">Estado</span><p><Badge tone="info">{p.status}</Badge> · prioridad {p.priority}</p></div><div className="card"><span className="muted small">Responsable</span><p>{p.manager}</p></div><div className="card"><span className="muted small">Progreso</span><div className="progress" style={{ marginTop: 10 }}><i style={{ width: p.progress + '%' }} /></div><p className="muted small">{p.progress}% · {fmtDate(p.start_date)} → {fmtDate(p.target_date)}</p></div></div>
    <div className="grid c2"><div className="card"><h3>Equipo</h3>{(p.team || []).map((c: any) => <p key={c.id} className="muted small" style={{ margin: '6px 0' }}>{c.name} — {c.specialty}</p>)}</div>
    <div className="card"><h3>Hitos</h3>{(p.milestones || []).map((m: any) => <p key={m.id} className="muted small" style={{ margin: '6px 0' }}>{m.done ? '✓' : '○'} {m.title} · {fmtDate(m.due_date)}</p>)}<h3 style={{ marginTop: 16 }}>Documentos de la organización</h3>{(p.documents || []).map((d: any) => <p key={d.id} className="muted small" style={{ margin: '6px 0' }}>{d.title} ({d.type})</p>)}</div></div></>);
}
export function TeamPage() { const [pageN, setPageN] = useState(1); const { data, loading, error } = useFetch<any>(`/team?page=${pageN}&pageSize=12`, [pageN]); if (loading) return <Loading />; if (error) return <ErrorBox message={error} />; return (<><h2>Equipo asignado</h2><div className="grid c3" style={{ marginTop: 18 }}>{data.items.map((c: any) => (<article className="card" key={c.id}><h3>{c.name}</h3><p className="muted small">{c.specialty} · {c.years} años de experiencia</p><Badge tone={c.availability === 'Disponible' ? 'success' : 'neutral'}>{c.availability}</Badge></article>))}</div><Pager page={pageN} setPage={setPageN} total={data.total} pageSize={data.pageSize} /></>); }
export function RequestsPage() {
  const [pageN, setPageN] = useState(1); const { data, loading, error, } = useFetch<any>(`/requests?page=${pageN}&pageSize=10`, [pageN]);
  const [form, setForm] = useState({ service_slug: 'desarrollo-de-software', problem: '', professionals: 2 }); const [msg, setMsg] = useState('');
  const submit = async (e: React.FormEvent) => { e.preventDefault(); await api('/requests', { method: 'POST', body: form }); setMsg('Solicitud creada. Recargá la página para verla en la lista.'); };
  if (loading) return <Loading />; if (error) return <ErrorBox message={error} />;
  return (<><h2>Solicitudes</h2><div className="tablewrap" style={{ marginTop: 16 }}><table><thead><tr><th>Código</th><th>Empresa</th><th>Servicio</th><th>Estado</th><th>Prioridad</th></tr></thead><tbody>{data.items.map((r: any) => (<tr key={r.id}><td>{r.request_code}</td><td>{r.company}</td><td>{r.service_slug}</td><td>{r.status}</td><td>{r.priority}</td></tr>))}</tbody></table></div><Pager page={pageN} setPage={setPageN} total={data.total} pageSize={data.pageSize} />
    <form className="card" onSubmit={submit} style={{ marginTop: 22 }}><h3>Nueva solicitud</h3><Field label="Servicio"><select className="input" value={form.service_slug} onChange={e => setForm({ ...form, service_slug: e.target.value })}>{['desarrollo-de-software', 'staff-augmentation', 'soporte-y-operaciones-it', 'ciberseguridad', 'data-y-analytics', 'business-process-outsourcing'].map(s => <option key={s}>{s}</option>)}</select></Field><Field label="¿Qué necesitás?"><textarea className="input" required rows={3} value={form.problem} onChange={e => setForm({ ...form, problem: e.target.value })} /></Field>{msg && <div className="alert ok" role="status">{msg}</div>}<Button type="submit">Crear solicitud</Button></form></>);
}
export function DocumentsPage() { const { data, loading, error } = useFetch<any>('/documents?pageSize=50'); if (loading) return <Loading />; if (error) return <ErrorBox message={error} />; return (<><h2>Documentos</h2><div className="tablewrap" style={{ marginTop: 16 }}><table><thead><tr><th>Título</th><th>Tipo</th><th>Archivo</th><th>Acción</th></tr></thead><tbody>{data.items.map((d: any) => (<tr key={d.id}><td>{d.title}</td><td>{d.type}</td><td>{d.file_name}</td><td>{d.file_name ? <a href={`/api/v1/documents/preview?name=${encodeURIComponent(d.file_name)}`} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>Previsualizar</a> : '—'}</td></tr>))}</tbody></table></div><p className="muted small" style={{ marginTop: 12 }}>La previsualización sirve solo archivos del área pública ficticia; las rutas fuera de ella se rechazan y quedan registradas.</p></>); }
export function TicketsPage() {
  const [pageN, setPageN] = useState(1); const { data, loading, error } = useFetch<any>(`/tickets?page=${pageN}&pageSize=10`, [pageN]);
  const [form, setForm] = useState({ subject: '', category: 'Soporte', priority: 'media', description: '' }); const [msg, setMsg] = useState('');
  const submit = async (e: React.FormEvent) => { e.preventDefault(); await api('/tickets', { method: 'POST', body: form }); setMsg('Ticket creado. Recargá la página para verlo.'); };
  if (loading) return <Loading />; if (error) return <ErrorBox message={error} />;
  return (<><h2>Tickets de soporte</h2><div className="tablewrap" style={{ marginTop: 16 }}><table><thead><tr><th>Asunto</th><th>Categoría</th><th>Prioridad</th><th>Estado</th><th>Responsable</th></tr></thead><tbody>{data.items.map((t: any) => (<tr key={t.id}><td>{t.subject}</td><td>{t.category}</td><td>{t.priority}</td><td>{t.status}</td><td>{t.assignee || 'Sin asignar'}</td></tr>))}</tbody></table></div><Pager page={pageN} setPage={setPageN} total={data.total} pageSize={data.pageSize} />
    <form className="card" onSubmit={submit} style={{ marginTop: 22 }}><h3>Crear ticket</h3><Field label="Asunto"><Input required value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} /></Field><Field label="Descripción"><textarea className="input" required rows={3} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} /></Field><Field label="Prioridad"><select className="input" value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })}>{['baja', 'media', 'alta'].map(x => <option key={x}>{x}</option>)}</select></Field>{msg && <div className="alert ok" role="status">{msg}</div>}<Button type="submit">Crear ticket</Button></form></>);
}
export function InvoicesPage() { const { data, loading, error } = useFetch<any>('/invoices?pageSize=50'); if (loading) return <Loading />; if (error) return <ErrorBox message={error} />; return (<><h2>Facturación</h2><p className="muted small">Facturas ficticias de demostración. No hay pasarela de pago.</p><div className="tablewrap" style={{ marginTop: 14 }}><table><thead><tr><th>Número</th><th>Concepto</th><th>Fecha</th><th>Importe</th><th>Estado</th></tr></thead><tbody>{data.items.map((i: any) => (<tr key={i.id}><td>{i.number}</td><td>{i.concept}</td><td>{fmtDate(i.issued_date)}</td><td>{i.currency} {Number(i.amount).toLocaleString()}</td><td><Badge tone={i.status === 'pagada' ? 'success' : i.status === 'vencida' ? 'danger' : 'warning'}>{i.status}</Badge></td></tr>))}</tbody></table></div></>); }
export function ActivityPage() { const { data, loading, error } = useFetch<any>('/activity?pageSize=50'); if (loading) return <Loading />; if (error) return <ErrorBox message={error} />; return (<><h2>Actividad</h2>{data.items.length === 0 && <p className="muted">Sin actividad registrada todavía.</p>}{data.items.map((a: any) => <p key={a.id} className="muted small">{a.action} — {a.detail} · {fmtDate(a.created_at)}</p>)}</>); }
export function ProfilePage() {
  const { user } = useAuth(); const [form, setForm] = useState({ name: '', last_name: '' }); const [msg, setMsg] = useState('');
  useEffect(() => { if (user) setForm({ name: user.name, last_name: user.last_name }); }, [user]);
  const submit = async (e: React.FormEvent) => { e.preventDefault(); await api('/profile', { method: 'PATCH', body: form }); setMsg('Perfil actualizado.'); };
  if (!user) return <Loading />;
  return (<><h2>Perfil y configuración</h2><p className="muted">{user.email} · rol {user.role}</p><form onSubmit={submit} style={{ maxWidth: 460, marginTop: 16 }}><Field label="Nombre"><Input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></Field><Field label="Apellidos"><Input value={form.last_name} onChange={e => setForm({ ...form, last_name: e.target.value })} /></Field>{msg && <div className="alert ok" role="status">{msg}</div>}<Button type="submit">Guardar cambios</Button></form></>);
}
