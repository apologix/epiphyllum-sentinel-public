import React, { useEffect, useState } from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import { Button } from './arc/button/button';
import { Badge } from './arc/badge/badge';
import { api } from '../api';
export { Button, Badge };

export function Logo({ size = 34 }: { size?: number }) {
  return (<span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true"><path d="M14 44c10 8 26 8 34-2 5-6 6-14 3-21l9-5-10-1c-3-5-9-8-15-8-11 0-19 8-20 18l-4 12c-1 3 0 5 3 7z" fill="#E8CD65"/><path d="M24 40c6 3 14 2 19-3-7 1-13-1-17-5-2 3-3 6-2 8z" fill="#090B0F" opacity="0.85"/><circle cx="40" cy="17" r="3" fill="#090B0F"/></svg>
    <span style={{ lineHeight: 1.05 }}><strong style={{ letterSpacing: 3, fontSize: 15 }}>CANARIO</strong><br /><span className="muted" style={{ letterSpacing: 2.4, fontSize: 9.5 }}>OUTSOURCING</span></span>
  </span>);
}
const NAV = [['/', 'Inicio'], ['/servicios', 'Servicios'], ['/industrias', 'Industrias'], ['/nosotros', 'Nosotros'], ['/casos-de-exito', 'Casos de éxito'], ['/carreras', 'Carreras'], ['/contacto', 'Contacto']];
export function Header() {
  const [open, setOpen] = useState(false);
  return (<header className="hdr"><div className="wrap hdr-in">
    <Link to="/" aria-label="Outsourcing Canario, inicio"><Logo /></Link>
    <button className="burger" aria-expanded={open} aria-label="Abrir menú" onClick={() => setOpen(!open)}>Menú</button>
    <nav className={'nav' + (open ? ' open' : '')} aria-label="Principal">
      {NAV.map(([to, label]) => <NavLink key={to} to={to} onClick={() => setOpen(false)}>{label}</NavLink>)}
      <Link to="/login" onClick={() => setOpen(false)}>Portal de clientes</Link>
      <Link to="/solicitar-propuesta" onClick={() => setOpen(false)}><Button size="sm">Solicitar propuesta</Button></Link>
    </nav></div></header>);
}
export function Footer() {
  return (<footer className="ftr"><div className="wrap">
    <div className="ftr-grid">
      <div><Logo /><p className="muted small" style={{ maxWidth: 300 }}>Talento que transforma. Operaciones que avanzan. Outsourcing de tecnología y procesos para empresas de Costa Rica y Latinoamérica. Empresa ficticia de demostración.</p></div>
      <div><strong>Servicios</strong><Link to="/servicios/desarrollo-de-software">Desarrollo de software</Link><Link to="/servicios/staff-augmentation">Staff augmentation</Link><Link to="/servicios/ciberseguridad">Ciberseguridad</Link><Link to="/servicios/data-y-analytics">Data &amp; Analytics</Link></div>
      <div><strong>Compañía</strong><Link to="/nosotros">Nosotros</Link><Link to="/casos-de-exito">Casos de éxito</Link><Link to="/carreras">Carreras</Link><Link to="/talento">Talento especializado</Link></div>
      <div><strong>Contacto</strong><span className="muted small">hola@canario.example<br />San José, Costa Rica (ficticio)<br />+506 0000-0000 (demostración)</span><Link to="/login">Portal de clientes</Link><Link to="/privacidad">Privacidad</Link><Link to="/terminos">Términos</Link></div>
    </div>
    <p className="muted small" style={{ marginTop: 26 }}>© 2026 Outsourcing Canario (empresa ficticia). Entorno de demostración: ningún dato es real.</p>
  </div></footer>);
}
export function PublicLayout({ children }: { children: React.ReactNode }) { return (<><Header /><main>{children}</main><Footer /></>); }
export function useFetch<T>(path: string, deps: any[] = []) {
  const [data, setData] = useState<T | null>(null); const [error, setError] = useState(''); const [loading, setLoading] = useState(true);
  useEffect(() => { let live = true; setLoading(true); api(path).then(({ data }) => { if (live) setData(data as T); }).catch(e => { if (live) setError(e.message); }).finally(() => { if (live) setLoading(false); }); return () => { live = false; }; }, deps);
  return { data, error, loading };
}
export function Loading() { return <div className="wrap section"><div className="skeleton" style={{ height: 120 }} /><div className="skeleton" style={{ height: 24, marginTop: 14, width: '60%' }} /></div>; }
export function ErrorBox({ message }: { message: string }) { return <div className="wrap section"><div className="alert error" role="alert">No pudimos cargar la información: {message}. Verificá que la API esté en línea.</div></div>; }
export function Field({ label, children }: { label: string; children: React.ReactNode }) { return <label className="field"><span>{label}</span>{children}</label>; }
export function useAuth() {
  const [user, setUser] = useState<any>(null); const [loading, setLoading] = useState(true);
  useEffect(() => { api('/auth/me').then(({ data }: any) => setUser(data.user)).catch(() => setUser(null)).finally(() => setLoading(false)); }, []);
  return { user, loading, setUser };
}
export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth(); const navigate = useNavigate();
  useEffect(() => { if (!loading && !user) navigate('/login'); }, [loading, user]);
  if (loading) return <Loading />; if (!user) return null;
  return <>{children}</>;
}
