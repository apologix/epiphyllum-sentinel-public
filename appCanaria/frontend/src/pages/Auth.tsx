import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, Field, Logo } from '../components/ui';
import { Input } from '../components/arc/input/input';
import { api } from '../api';

function Split({ children, title }: { children: React.ReactNode; title: string }) {
  return (<div className="split">
    <div style={{ background: 'var(--surface)', borderRight: '1px solid var(--border)', padding: 40, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      <Logo size={54} /><h2 style={{ marginTop: 24 }}>{title}</h2>
      <p className="muted" style={{ maxWidth: 380 }}>Tu equipo, tus proyectos y tu operación en un solo lugar. Canario Workspace es el portal privado de nuestros clientes y colaboradores.</p>
      <p className="muted small">Talento que transforma. Operaciones que avanzan.</p>
    </div>
    <div style={{ padding: 40, display: 'flex', flexDirection: 'column', justifyContent: 'center', maxWidth: 520, width: '100%', margin: '0 auto' }}>{children}</div>
  </div>);
}
export function LoginPage() {
  const navigate = useNavigate(); const [form, setForm] = useState({ email: '', password: '' }); const [show, setShow] = useState(false); const [msg, setMsg] = useState<{ kind: string; text: string }>({ kind: '', text: '' }); const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => { e.preventDefault(); setBusy(true); setMsg({ kind: '', text: '' });
    try { const { data } = await api('/auth/login', { method: 'POST', body: form }); navigate(data.user.role === 'admin' || data.user.role === 'operations' ? '/operations' : '/portal'); }
    catch (err: any) { setMsg({ kind: 'error', text: err.status === 429 ? 'Demasiados intentos fallidos. Esperá unos minutos e intentalo de nuevo.' : err.message }); } finally { setBusy(false); } };
  return (<Split title="Bienvenido de nuevo.">
    <h2>Portal de clientes</h2><p className="muted">Ingresá con tu cuenta de Canario Workspace.</p>
    <form onSubmit={submit} style={{ marginTop: 18 }}>
      <Field label="Correo electrónico"><Input required type="email" autoComplete="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></Field>
      <Field label="Contraseña"><span style={{ display: 'flex', gap: 8 }}><span style={{ flex: 1 }}><Input required type={show ? 'text' : 'password'} autoComplete="current-password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></span><Button type="button" variant="ghost" size="sm" onClick={() => setShow(!show)}>{show ? 'Ocultar' : 'Mostrar'}</Button></span></Field>
      {msg.text && <div className="alert error" role="alert">{msg.text}</div>}
      <Button type="submit" disabled={busy} style={{ width: '100%' }}>{busy ? 'Ingresando…' : 'Ingresar'}</Button>
    </form>
    <p className="muted small" style={{ marginTop: 16 }}><Link to="/recuperar-contrasena" style={{ color: 'var(--accent)' }}>Recuperar contraseña</Link> · ¿Todavía no tenés cuenta? <Link to="/registro" style={{ color: 'var(--accent)' }}>Registrate</Link></p>
    <p className="muted small">Cuentas de demostración del laboratorio: cliente@novapagos.example (cliente), operaciones@canario.example (operaciones). Las contraseñas las entrega el instructor; no están en el código.</p>
  </Split>);
}
export function RegisterPage() {
  const navigate = useNavigate(); const [form, setForm] = useState({ name: '', last_name: '', company: '', email: '', password: '', confirm: '', terms: false }); const [msg, setMsg] = useState<{ kind: string; text: string }>({ kind: '', text: '' });
  const submit = async (e: React.FormEvent) => { e.preventDefault(); if (form.password !== form.confirm) { setMsg({ kind: 'error', text: 'Las contraseñas no coinciden.' }); return; } if (!form.terms) { setMsg({ kind: 'error', text: 'Aceptá los términos para crear la cuenta.' }); return; }
    try { await api('/auth/register', { method: 'POST', body: form }); setMsg({ kind: 'ok', text: 'Cuenta creada. Ya podés iniciar sesión.' }); setTimeout(() => navigate('/login'), 900); } catch (err: any) { setMsg({ kind: 'error', text: err.message }); } };
  return (<Split title="Creá tu cuenta de cliente.">
    <h2>Registro</h2><p className="muted">Tu cuenta nace con rol de cliente y acceso solo a tu organización.</p>
    <form onSubmit={submit} style={{ marginTop: 18 }}>
      <Field label="Nombre"><Input required value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} autoComplete="given-name" /></Field>
      <Field label="Apellidos"><Input required value={form.last_name} onChange={e => setForm({ ...form, last_name: e.target.value })} autoComplete="family-name" /></Field>
      <Field label="Empresa"><Input value={form.company} onChange={e => setForm({ ...form, company: e.target.value })} autoComplete="organization" /></Field>
      <Field label="Correo"><Input required type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} autoComplete="email" /></Field>
      <Field label="Contraseña (mínimo 10 caracteres)"><Input required type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} autoComplete="new-password" /></Field>
      <Field label="Confirmación"><Input required type="password" value={form.confirm} onChange={e => setForm({ ...form, confirm: e.target.value })} autoComplete="new-password" /></Field>
      <label style={{ display: 'flex', gap: 8, fontSize: 14 }}><input type="checkbox" checked={form.terms} onChange={e => setForm({ ...form, terms: e.target.checked })} /> Acepto los <Link to="/terminos" style={{ color: 'var(--accent)' }}>términos de uso del entorno</Link>.</label>
      {msg.text && <div className={`alert ${msg.kind}`} role="status">{msg.text}</div>}
      <div style={{ marginTop: 14 }}><Button type="submit">Crear cuenta</Button></div>
    </form></Split>);
}
export function ForgotPage() {
  const [email, setEmail] = useState(''); const [msg, setMsg] = useState('');
  const submit = async (e: React.FormEvent) => { e.preventDefault(); const { data } = await api('/auth/forgot-password', { method: 'POST', body: { email } }); setMsg(data.message); };
  return (<Split title="Recuperá tu acceso."><h2>Recuperar contraseña</h2><p className="muted">En este laboratorio no se envían correos reales: el instructor entrega el enlace desde la salida local privada del servidor.</p>
    <form onSubmit={submit} style={{ marginTop: 18 }}><Field label="Correo de tu cuenta"><Input required type="email" value={email} onChange={e => setEmail(e.target.value)} /></Field>{msg && <div className="alert ok" role="status">{msg}</div>}<Button type="submit">Solicitar restablecimiento</Button></form></Split>);
}
export function ResetPage() {
  const [form, setForm] = useState({ token: '', password: '' }); const [msg, setMsg] = useState<{ kind: string; text: string }>({ kind: '', text: '' }); const navigate = useNavigate();
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try { await api('/auth/reset-password', { method: 'POST', body: form }); setMsg({ kind: 'ok', text: 'Contraseña restablecida. Iniciá sesión.' }); setTimeout(() => navigate('/login'), 900); } catch (err: any) { setMsg({ kind: 'error', text: err.message }); } };
  return (<Split title="Nueva contraseña."><h2>Restablecer contraseña</h2>
    <form onSubmit={submit} style={{ marginTop: 18 }}><Field label="Token entregado por el instructor"><Input required value={form.token} onChange={e => setForm({ ...form, token: e.target.value })} /></Field><Field label="Nueva contraseña (mínimo 10)"><Input required type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></Field>{msg.text && <div className={`alert ${msg.kind}`} role="status">{msg.text}</div>}<Button type="submit">Restablecer</Button></form></Split>);
}
