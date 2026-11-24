import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Button, Badge, Field, Loading, ErrorBox, useFetch } from '../components/ui';
import { Input } from '../components/arc/input/input';
import { api } from '../api';

export function CareersPage() {
  const [f, setF] = useState({ q: '', area: '', modality: '', level: '' });
  const qs = new URLSearchParams(Object.fromEntries(Object.entries(f).filter(([, v]) => v))).toString();
  const { data, loading, error } = useFetch<any>('/jobs' + (qs ? '?' + qs : ''), [qs]);
  return (<section className="section"><div className="wrap"><h2>Carreras en Canario</h2><p className="muted" style={{ maxWidth: 620 }}>Vacantes ficticias de demostración, servidas desde la base de datos. Si te postulás, tu candidatura llega al panel de operaciones.</p>
    <form className="card" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(160px,1fr))', gap: 12, margin: '22px 0' }} aria-label="Filtros de vacantes">
      <Field label="Buscar"><Input value={f.q} onChange={e => setF({ ...f, q: e.target.value })} placeholder="React, datos, SOC…" /></Field>
      <Field label="Área"><select className="input" value={f.area} onChange={e => setF({ ...f, area: e.target.value })}><option value="">Todas</option>{['Tecnología', 'Datos', 'Ciberseguridad', 'Operaciones', 'Diseño', 'BPO'].map(a => <option key={a}>{a}</option>)}</select></Field>
      <Field label="Modalidad"><select className="input" value={f.modality} onChange={e => setF({ ...f, modality: e.target.value })}><option value="">Todas</option>{['Remoto', 'Híbrido', 'En sitio'].map(a => <option key={a}>{a}</option>)}</select></Field>
      <Field label="Experiencia"><select className="input" value={f.level} onChange={e => setF({ ...f, level: e.target.value })}><option value="">Toda</option>{['Junior', 'Semi-senior', 'Senior'].map(a => <option key={a}>{a}</option>)}</select></Field>
    </form>
    {loading ? <Loading /> : error ? <ErrorBox message={error} /> : (<div className="grid c2">{data.items.map((j: any) => (<article className="card" key={j.id}><div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}><Badge outline>{j.area}</Badge><Badge outline>{j.modality}</Badge><Badge outline>{j.level}</Badge></div><h3 style={{ marginTop: 10 }}>{j.title}</h3><p className="muted small">{j.location} · {j.tech}</p><Link to={`/carreras/${j.slug}`} style={{ color: 'var(--accent)' }}>Ver vacante y postularme →</Link></article>))}</div>)}
    {data && data.items.length === 0 && <p className="muted">Ninguna vacante coincide con esos filtros.</p>}
  </div></section>);
}
export function CareerDetail() {
  const { slug } = useParams(); const { data: j, loading, error } = useFetch<any>(`/jobs/${slug}`, [slug]);
  const [form, setForm] = useState({ name: '', last_name: '', email: '', phone: '', country: 'Costa Rica', experience: '', profile: '', portfolio_url: '', cover_letter: '', cv_file_name: '' });
  const [msg, setMsg] = useState<{ kind: string; text: string }>({ kind: '', text: '' });
  if (loading) return <Loading />; if (error || !j) return <ErrorBox message={error || 'Vacante no encontrada'} />;
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try { await api('/applications', { method: 'POST', body: { ...form, job_id: j.id } }); setMsg({ kind: 'ok', text: 'Candidatura recibida. El equipo de operaciones la revisará (demostración).' }); } catch (err: any) { setMsg({ kind: 'error', text: err.message }); } };
  return (<section className="section"><div className="wrap hero-grid">
    <div><Link to="/carreras" className="muted small">← Carreras</Link><h2 style={{ marginTop: 12 }}>{j.title}</h2><p className="muted">{j.description}</p><p className="muted small">{j.location} · {j.modality} · {j.level} · Tecnologías: {j.tech}</p></div>
    <form className="card" onSubmit={submit} aria-label="Formulario de postulación">
      <h3>Postularme</h3>
      <Field label="Nombre"><Input required value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
      <Field label="Apellidos"><Input required value={form.last_name} onChange={e => setForm({ ...form, last_name: e.target.value })} /></Field>
      <Field label="Correo"><Input required type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></Field>
      <Field label="Teléfono (ficticio)"><Input value={form.phone} onChange={e => setForm({ ...form, phone: e.target.value })} /></Field>
      <Field label="País"><Input value={form.country} onChange={e => setForm({ ...form, country: e.target.value })} /></Field>
      <Field label="Experiencia"><Input value={form.experience} onChange={e => setForm({ ...form, experience: e.target.value })} placeholder="Ej.: 4 años en backend" /></Field>
      <Field label="Perfil profesional"><textarea className="input" rows={3} value={form.profile} onChange={e => setForm({ ...form, profile: e.target.value })} /></Field>
      <Field label="URL de portafolio"><Input value={form.portfolio_url} onChange={e => setForm({ ...form, portfolio_url: e.target.value })} /></Field>
      <Field label="Carta breve"><textarea className="input" rows={3} value={form.cover_letter} onChange={e => setForm({ ...form, cover_letter: e.target.value })} /></Field>
      <Field label="CV de demostración (solo el nombre del archivo; no subas documentos reales)"><Input value={form.cv_file_name} onChange={e => setForm({ ...form, cv_file_name: e.target.value })} placeholder="cv-nombre.pdf" /></Field>
      {msg.text && <div className={`alert ${msg.kind}`} role="status">{msg.text}</div>}
      <Button type="submit">Enviar candidatura</Button>
    </form></div></section>);
}
export function ContactPage() {
  const [form, setForm] = useState({ name: '', email: '', phone: '', company: '', department: '', subject: '', message: '', contact_preference: 'correo' });
  const [msg, setMsg] = useState<{ kind: string; text: string }>({ kind: '', text: '' });
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try { const { data } = await api('/contact', { method: 'POST', body: form }); setMsg({ kind: 'ok', text: `Mensaje registrado con el código ${data.request_code}.` }); } catch (err: any) { setMsg({ kind: 'error', text: err.message }); } };
  return (<section className="section"><div className="wrap" style={{ maxWidth: 720 }}><h2>Contacto</h2><p className="muted">Escribinos y un especialista te responde. Este formulario guarda tu mensaje en la base de datos de la empresa (ficticia).</p>
    <form onSubmit={submit} style={{ marginTop: 20 }}>
      <Field label="Nombre completo"><Input required value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
      <Field label="Correo"><Input required type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></Field>
      <Field label="Teléfono"><Input value={form.phone} onChange={e => setForm({ ...form, phone: e.target.value })} /></Field>
      <Field label="Empresa"><Input value={form.company} onChange={e => setForm({ ...form, company: e.target.value })} /></Field>
      <Field label="Departamento"><Input value={form.department} onChange={e => setForm({ ...form, department: e.target.value })} /></Field>
      <Field label="Asunto"><Input value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} /></Field>
      <Field label="Mensaje"><textarea className="input" required rows={5} value={form.message} onChange={e => setForm({ ...form, message: e.target.value })} /></Field>
      <Field label="Preferencia de contacto"><select className="input" value={form.contact_preference} onChange={e => setForm({ ...form, contact_preference: e.target.value })}><option value="correo">Correo</option><option value="telefono">Teléfono</option></select></Field>
      {msg.text && <div className={`alert ${msg.kind}`} role="status">{msg.text}</div>}
      <Button type="submit">Enviar mensaje</Button>
    </form></div></section>);
}
export function QuotePage() {
  const { data } = useFetch<any>('/services');
  const [step, setStep] = useState(0); const [msg, setMsg] = useState<{ kind: string; text: string }>({ kind: '', text: '' });
  const [b, setB] = useState<any>({ company: '', industry: 'tecnologia', country: 'Costa Rica', size: '11-50', contact_name: '', email: '', service_slug: 'desarrollo-de-software', problem: '', professionals: 2, technologies: '', modality: 'Remoto', start_date: '', duration: '6 meses', budget: '', priority: 'media', comments: '' });
  const set = (k: string) => (e: any) => setB({ ...b, [k]: e.target.value });
  const steps = ['Organización', 'Necesidad', 'Alcance', 'Revisión'];
  const submit = async () => { try { const { data: r } = await api('/quotes', { method: 'POST', body: b }); setMsg({ kind: 'ok', text: `Solicitud registrada con el código ${r.request_code}. Aparece de inmediato en Canario Operations.` }); } catch (err: any) { setMsg({ kind: 'error', text: err.message }); } };
  return (<section className="section"><div className="wrap" style={{ maxWidth: 760 }}><h2>Solicitar una propuesta</h2>
    <div className="steps">{steps.map((s, i) => <span key={s} className={`badge ${i === step ? 'on' : ''}`}>{`${i + 1}. ${s}`}</span>)}</div>
    {step === 0 && (<><Field label="Nombre de la empresa"><Input required value={b.company} onChange={set('company')} /></Field><Field label="Industria"><select className="input" value={b.industry} onChange={set('industry')}>{['finanzas', 'salud', 'comercio', 'educacion', 'tecnologia', 'logistica'].map(x => <option key={x}>{x}</option>)}</select></Field><Field label="País"><Input value={b.country} onChange={set('country')} /></Field><Field label="Tamaño de la empresa"><select className="input" value={b.size} onChange={set('size')}>{['1-10', '11-50', '51-200', '201-500', '500+'].map(x => <option key={x}>{x}</option>)}</select></Field><Field label="Nombre de contacto"><Input value={b.contact_name} onChange={set('contact_name')} /></Field><Field label="Correo corporativo"><Input type="email" value={b.email} onChange={set('email')} /></Field></>)}
    {step === 1 && (<><Field label="Tipo de servicio"><select className="input" value={b.service_slug} onChange={set('service_slug')}>{(data?.items || []).map((s: any) => <option key={s.slug} value={s.slug}>{s.name}</option>)}</select></Field><Field label="Descripción del problema"><textarea className="input" rows={4} value={b.problem} onChange={set('problem')} /></Field><Field label="Profesionales estimados"><Input type="number" min={1} value={b.professionals} onChange={set('professionals')} /></Field><Field label="Tecnologías requeridas"><Input value={b.technologies} onChange={set('technologies')} /></Field><Field label="Modalidad"><select className="input" value={b.modality} onChange={set('modality')}>{['Remoto', 'Híbrido', 'En sitio'].map(x => <option key={x}>{x}</option>)}</select></Field><Field label="Fecha de inicio"><Input type="date" value={b.start_date} onChange={set('start_date')} /></Field></>)}
    {step === 2 && (<><Field label="Duración estimada"><Input value={b.duration} onChange={set('duration')} /></Field><Field label="Presupuesto aproximado (USD)"><Input value={b.budget} onChange={set('budget')} /></Field><Field label="Prioridad"><select className="input" value={b.priority} onChange={set('priority')}>{['baja', 'media', 'alta'].map(x => <option key={x}>{x}</option>)}</select></Field><Field label="Comentarios"><textarea className="input" rows={3} value={b.comments} onChange={set('comments')} /></Field></>)}
    {step === 3 && (<div className="card"><h3>Revisá tu solicitud</h3><p className="muted small">{b.company} · {b.industry} · {b.country} · contacto {b.contact_name} ({b.email})</p><p className="muted small">Servicio: {b.service_slug} · {b.professionals} profesionales · {b.modality} · inicio {b.start_date || 'a convenir'} · duración {b.duration} · prioridad {b.priority}</p><p className="muted small">{b.problem}</p>{msg.text && <div className={`alert ${msg.kind}`} role="status">{msg.text}</div>}<Button onClick={submit}>Confirmar y enviar solicitud</Button></div>)}
    <div style={{ display: 'flex', gap: 10, marginTop: 18 }}>{step > 0 && <Button variant="secondary" onClick={() => setStep(step - 1)}>Atrás</Button>}{step < 3 && <Button onClick={() => setStep(step + 1)}>Continuar</Button>}</div>
  </div></section>);
}
export function TalentPage() {
  const [q, setQ] = useState(''); const [res, setRes] = useState<any>(null); const [err, setErr] = useState('');
  const search = async (e: React.FormEvent) => { e.preventDefault(); try { const { data } = await api('/talent/search?q=' + encodeURIComponent(q)); setRes(data); setErr(''); } catch (e2: any) { setErr(e2.message); } };
  return (<section className="section"><div className="wrap"><h2>Explorador de talento especializado</h2><p className="muted" style={{ maxWidth: 620 }}>Buscá especialistas disponibles por nombre o explorá el directorio completo. Los perfiles son ficticios y públicos para clientes interesados.</p>
    <form onSubmit={search} style={{ display: 'flex', gap: 10, margin: '20px 0', flexWrap: 'wrap' }}><div style={{ flex: '1 1 280px' }}><Input value={q} onChange={e => setQ(e.target.value)} placeholder="Ej.: María, Diego, Ana" aria-label="Buscar talento por nombre" /></div><Button type="submit">Buscar talento</Button></form>
    {err && <div className="alert error" role="alert">{err}</div>}
    {res && (<div className="tablewrap"><table><thead><tr><th>Nombre</th><th>Especialidad</th><th>Experiencia</th><th>Disponibilidad</th><th>Habilidad destacada</th></tr></thead><tbody>{res.items.map((t: any) => (<tr key={t.id}><td>{t.name}</td><td>{t.specialty}</td><td>{t.years} años</td><td>{t.availability}</td><td>{t.skills}</td></tr>))}</tbody></table></div>)}
    {res && res.items.length === 0 && <p className="muted">Sin resultados para esa búsqueda.</p>}
  </div></section>);
}
export function LegalPage({ kind }: { kind: 'privacidad' | 'terminos' }) {
  return (<section className="section"><div className="wrap" style={{ maxWidth: 760 }}>{kind === 'privacidad' ? (<><h2>Política de privacidad (demostración)</h2><p className="muted">Outsourcing Canario es una empresa ficticia creada para un taller. Este entorno usa exclusivamente datos simulados: ningún formulario recoge información real de personas y ningún dato sale del laboratorio. Los registros de la aplicación se conservan solo para el ejercicio y se eliminan al restaurar la VM.</p></>) : (<><h2>Términos de uso del entorno</h2><p className="muted">Este sitio es un entorno de entrenamiento aislado. Las cuentas, empresas, vacantes y cifras son ficticias. El acceso está limitado a participantes autorizados del laboratorio; el modo vulnerable solo puede activarse en la VM aislada bajo control del instructor.</p></>)}</div></section>);
}
