import React, { useState, useEffect, useRef, useCallback } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/source-sans-3/400.css";
import "@fontsource/source-sans-3/600.css";
import "@/components/arc/foundation.css";
import "./style.css";
import { ServiceCatalog, ServicePicker, ToggleSwitch } from "./services";
import { AnalysisPanel } from "./analysis";
import { CveTab } from "./cve";
import { ClassificationBadge, CLASSIFICATION_LABELS } from "./observability";
import { Sparkline } from "@/components/arc/sparkline/sparkline";
import { MetricCard } from "@/components/arc/metric-card/metric-card";
import { LineChart } from "@/components/arc/line-chart/line-chart";
import { DonutChart } from "@/components/arc/donut-chart/donut-chart";
import { Gauge } from "@/components/arc/gauge/gauge";
import { UsageMeter } from "@/components/arc/usage-meter/usage-meter";
import { Timeline } from "@/components/arc/timeline/timeline";
import { Badge as ArcBadge } from "@/components/arc/badge/badge";
import { Button as ArcButton } from "@/components/arc/button/button";
import { aiCheckFingerprint, aiCheckView, type AiCheckResult } from "./ai-check";
import {
  defaultBase,
  emptySpecFields,
  findCatalogEntry,
  missingSpecFields,
  modelSuggestions,
  providerLabel,
  specFieldsFrom,
  specFromFields,
  specIsValid,
  type ModelCatalog,
  type ModelSpec,
  type SpecFields,
} from "./model-catalog";
import { EmptyState } from "@/components/arc/empty-state/empty-state";
import { Dialog as ArcDialog, DialogContent as ArcDialogContent } from "@/components/arc/dialog/dialog";
import { Alert as ArcAlert } from "@/components/arc/alert/alert";
import { Select as ArcSelect } from "@/components/arc/select/select";
import { Input as ArcInput } from "@/components/arc/input/input";
import { Textarea as ArcTextarea } from "@/components/arc/textarea/textarea";
import { Checkbox as ArcCheckbox } from "@/components/arc/checkbox/checkbox";
import { Slider as ArcSlider } from "@/components/arc/slider/slider";
import { Tabs as ArcTabs, TabsList as ArcTabsList, TabsTrigger as ArcTabsTrigger, TabsContent as ArcTabsContent } from "@/components/arc/tabs/tabs";
import { SortableDataTable as ArcTable } from "@/components/arc/sortable-data-table/sortable-data-table";
import { BarChart } from "@/components/arc/bar-chart/bar-chart";
import { SentinelLogo } from "./logo";
import { ToastHost, notifyToast } from "./toast";
import { StreamPanel, WafflePanel, WAFFLE_COLORS } from "./charts05";
import { buildStreamWindow } from "./stream-window";
import { LangProvider, LangSwitch, locale } from "./i18n";
type Data = Record<string, any>;
let csrf = "";
async function api(path: string, method = "GET", body?: unknown) {
  const res = await fetch("/api/v1" + path, {
    method,
    headers:
      method === "GET"
        ? {}
        : { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok)
    throw new Error(
      data.error?.message || "No se pudo completar la solicitud.",
    );
  return data;
}
const states: Record<string, string> = {
  mock: "Histórico",
  live: "IA externa",
  local: "Local por política",
  unavailable: "Original histórico no recuperado",
  mixed: "Mixto histórico",
  in_progress: "En curso",
  inconclusive: "No concluyente",
  blocked: "Bloqueado",
  pending: "Pendiente",
  preparing: "Recuperando fuentes",
  reserved: "Reservado",
  in_flight: "Generando",
  succeeded: "Completado",
  cached: "Caché",
  blocked_config: "Bloqueado",
  skipped_budget: "Presupuesto agotado",
  unknown: "Envío ambiguo, sin reenvío",
  failed: "Falló el proveedor",
  stopped: "Detenido por el operador",
  building: "Indexando",
  ready: "Lista",
  draft: "Borrador",
};
const reviewReasons: Record<string,string> = {
  service_unassigned: "Los registros de esta incidencia todavía no están asignados a un servicio.",
  generation_paused: "Generación pausada por el operador; no se envían solicitudes externas.",
  provider_not_configured: "Configure un proveedor y autorice el lote para generar análisis nuevos.",
  credential_missing: "Falta la credencial del perfil fijado.",
  capability_tariff_or_bound_unverified: "Faltan capacidades, tarifa o límites verificados.",
  live_not_authorized_or_scope_exhausted: "Trabajo bloqueado por una configuración anterior; revise su estado antes de repetirlo.",
  budget_insufficient: "El saldo no alcanza para reservar el bloque completo.",
  session_limit_reached: "Se alcanzó el límite monetario de la sesión; ajustalo en Ajustes para nuevas solicitudes.",
  primary_review_policy_denied: "La política de revisión primaria denegó el envío.",
  ambiguous_request_no_retry: "El envío externo quedó ambiguo; no se reenvía automáticamente.",
  partial_coverage_missing_ids: "Respuesta parcial: se conservaron los resultados válidos y faltan segmentos.",
  hostile_text_local: "Texto hostil: permanece local por política.",
  sensitive_text_local: "Texto sensible: permanece local por política.",
  invalid_utf8: "La entrada no es texto UTF8 válido.",
  record_exceeds_1mib_reference_only: "Supera 1 MiB: se conserva referencia verificable, sin revisión IA.",
  historical_original_not_recovered: "El original histórico todavía no pudo recuperarse.",
  operator_stopped: "Detenido por el operador; no se enviará.",
  circuit_open: "Pausa temporal: tres respuestas fallidas o ambiguas seguidas.",
  invalid_provider_response: "La API respondió, pero la respuesta no cumplió el contrato.",
};
const reviewReason = (reason?:string) => reason ? reviewReasons[reason] || reason : "";
const severity: Record<string, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  informational: "Informativa",
};
const time = (s: string) =>
  s
    ? new Date(s).toLocaleString(locale(), { timeZone: "America/Costa_Rica" })
    : "—";
function Badge({ value }: { value: string }) {
  // Insignia de Arc con el tono según la clase de valor; el texto visible no
  // cambia (severidad, estado u origen, como antes).
  const tone =
    value === "critical" || value === "high" || value === "failed"
      ? "danger"
      : value === "medium" || value === "pending" || value === "queued"
        ? "warning"
        : value === "low" || value === "completed"
          ? "success"
          : value === "informational" || value === "live"
            ? "info"
            : "neutral";
  return (
    <ArcBadge tone={tone} pill>
      {severity[value] || states[value] || value}
    </ArcBadge>
  );
}
function Flower() {
  // UI-ARC-05 (punto 6): logo propio (hoja de epiphyllum + ojo sentinela).
  return <SentinelLogo size={42} />;
}
function NavIcon({ index }: { index: number }) {
  const paths = [
    "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    "M4 4h16v12H9l-5 4V4zM8 8h8M8 12h5",
    "M8 5h13M8 12h13M8 19h13M3 5h.01M3 12h.01M3 19h.01",
    "M4 4h6a3 3 0 0 1 3 3v14a4 4 0 0 0-4-3H4V4zM13 7a3 3 0 0 1 3-3h5v14h-4a4 4 0 0 0-4 3",
    "M4 5h16v6H4zM4 14h16v6H4zM7 8h.01M7 17h.01",
    "M4 18V9M10 18V4M16 18v-7M22 18H2",
    "M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3zM9 11.5l2 2 4-4.5",
    "M4 7h16M4 17h16M9 4v6M16 14v6",
    "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.51 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9c.24.6.86 1 1.51 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1z",
  ];
  return (
    <svg
      width="19"
      height="19"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[index]} />
    </svg>
  );
}
export function SafeText({ value }: { value: unknown }) {
  return (
    <span className="prewrap">
      {typeof value === "string" ? value : JSON.stringify(value, null, 2)}
    </span>
  );
}
function App() {
  const [session, setSession] = useState(false),
    [loginChecked, setLoginChecked] = useState(false),
    [secret, setSecret] = useState(""),
    [error, setError] = useState(""),
    [view, setView] = useState("Resumen"),
    [selected, setSelected] = useState<string | null>(null),
    [status, setStatus] = useState<Data>({}),
    [connected, setConnected] = useState(false),
    [refresh, setRefresh] = useState(0);
  const [navOpen, setNavOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => { try { return localStorage.getItem("sentinel-sidebar") === "collapsed"; } catch { return false; } });
  const toggleSidebar = () => setSidebarCollapsed((v) => { const next = !v; try { localStorage.setItem("sentinel-sidebar", next ? "collapsed" : "expanded"); } catch {} return next; });
  const seq = useRef(0);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    api("/session")
      .then((s) => {
        csrf = s.csrf_token;
        setSession(true);
      })
      .catch(() => {})
      .finally(() => setLoginChecked(true));
  }, []);
  useEffect(() => {
    if (!session) return;
    const es = new EventSource("/api/v1/stream");
    const onOpen = () => {
      setConnected(true);
      setRefresh((v) => v + 1);
    };
    es.onopen = onOpen;
    es.onerror = () => setConnected(false);
    const handler = (e: MessageEvent) => {
      const id = Number(e.lastEventId);
      if (id <= seq.current) return;
      seq.current = id;
      if (refreshTimer.current === null) {
        refreshTimer.current = setTimeout(() => {
          setRefresh((v) => v + 1);
          refreshTimer.current = null;
        }, 250);
      }
    };
    [
      "coverage.updated",
      "business_rules.updated",
      "report.created",
      "report.updated",
      "notification.updated",
      "conversation.updated",
      "knowledge.build.updated",
      "knowledge.activated",
      "settings.updated",
      "service.updated",
      "service.deleted",
      "source.updated",
      "source.deleted",
      "budget.updated",
      "dashboard.notes.updated",
    ].forEach((k) => es.addEventListener(k, handler as EventListener));
    es.addEventListener("resync_required", () => {
      seq.current = 0;
      setRefresh((v) => v + 1);
    });
    return () => {
      es.close();
    };
  }, [session]);
  useEffect(() => {
    if (!session) return;
    let cancelled=false;
    const load=()=>{void api("/status").then(s=>{if(!cancelled)setStatus(s);}).catch(()=>{});};
    load();
    const timer=setInterval(load,15000);
    return ()=>{cancelled=true;clearInterval(timer);};
  },[session,refresh]);
  async function login(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const s = await api("/session", "POST", { secret });
      csrf = s.csrf_token;
      setSecret("");
      setSession(true);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  const navigation = (
    <>
      <div className="brand">
        <Flower />
        <div className="brand-text">
          Epiphyllum<strong>Sentinel</strong>
        </div>
        <ArcButton type="button" variant="ghost" size="sm" className="sidebar-toggle" aria-label={sidebarCollapsed ? "Expandir barra lateral" : "Colapsar barra lateral"} aria-expanded={!sidebarCollapsed} title={sidebarCollapsed ? "Expandir barra lateral" : "Colapsar barra lateral"} onClick={toggleSidebar}>{sidebarCollapsed ? "»" : "«"}</ArcButton>
      </div>
      <p className="nav-caption">Observación e investigación</p>
      <nav aria-label="Navegación principal">
        {[
          "Resumen",
          "Incidencias",
          "Eventos",
          "Conocimiento",
          "Servicios",
          "Análisis",
          "CVE",
          "Estado y costos",
          "Ajustes",
        ].map((name, i) => (
          <ArcButton
            variant="ghost"
            key={name}
            className={
              (view === name ? "active " : "") +
              (i === 8 ? "settings-link" : "")
            }
            onClick={() => {
              setView(name);
              setSelected(null);
              setNavOpen(false);
            }}
            aria-current={view === name ? "page" : undefined}
            aria-label={name}
            title={name}
          >
            <NavIcon index={i} />
            {name}
          </ArcButton>
        ))}
      </nav>
      <div className="nav-note">
        Fuentes configuradas por el operador.
        <br />
        Las decisiones las toma una persona.
      </div>
      <div className="nav-lang"><LangSwitch /></div>
      <ArcButton
        className="logout"
        aria-label="Cerrar sesión"
        title="Cerrar sesión"
        onClick={async () => {
          try {
            await api("/session", "DELETE");
          } catch {
            // Cerrar sesión localmente aunque la API no responda.
          } finally {
            setSession(false);
          }
        }}
      >
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="m16 17 5-5-5-5" /><path d="M21 12H9" /></svg>
        Cerrar sesión
      </ArcButton>
    </>
  );
  if (!loginChecked)
    return (
      <main className="login">
        <p>Comprobando sesión local…</p>
      </main>
    );
  if (!session)
    return (
      <main className="login">
        <div className="lang-corner"><LangSwitch /></div>
        <section>
          <div className="login-brand">
            <Flower />
            <h1>Epiphyllum Sentinel</h1>
          </div>
          <h2>Investigar con evidencia</h2>
          <p>
            Aplicación local de laboratorio. Ingrese el secreto administrativo
            de su archivo .env.
          </p>
          <form onSubmit={login}>
            <ArcInput
              label="Secreto de acceso"
              id="secret"
              type="password"
              autoComplete="current-password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              required
            />
            <ArcButton type="submit">Iniciar sesión</ArcButton>
          </form>
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
          <small>
            Producto informativo. Sin herramientas ni acciones sobre sistemas.
          </small>
        </section>
      </main>
    );
  return (
    <div className={"app" + (sidebarCollapsed ? " sidebar-collapsed" : "")}>
      <a className="skip" href="#main">
        Saltar al contenido
      </a>
      <aside className={"sidebar" + (sidebarCollapsed ? " collapsed" : "")}>{navigation}</aside>
      <ToastHost />
      <ArcDialog open={navOpen} onOpenChange={setNavOpen}>
        <ArcDialogContent title="Navegación" className="mobile-nav">
          {navigation}
        </ArcDialogContent>
      </ArcDialog>
      <div className={"workspace " + (selected ? "workspace-incident" : "")}>
        <header className="topbar">
          <ArcButton
            variant="secondary"
            className="mobile-menu"
            onClick={() => setNavOpen(true)}
          >
            Menú
          </ArcButton>
          <span className="breadcrumb">Investigación local / {view}</span>
          <div className="status-line">
            <span>Fuentes de laboratorio</span>
            <Badge value={status.generation_paused ? "IA pausada" : status.mode === "live" ? "API configurada" : "Sin API"} />
            <span className={connected ? "connection" : "offline"}>
              {connected ? "● Conectado" : "○ Reconectando"}
            </span>
            <LangSwitch />
            <Notifications refresh={refresh} onOpen={(id) => { setView("Incidencias"); setSelected(id); }} />
          </div>
        </header>
        <main
          id="main"
          className={
            selected
              ? "incident-page"
              : view === "Resumen"
                ? "dashboard-view"
                : undefined
          }
        >
          {!selected && (
            <div className="heading">
              <div>
                <h1>{view}</h1>
                <p>
                  {
                    (
                      {
                        Resumen:
                          "Actividad, prioridades y costos de la demo, en un solo lugar.",
                        Incidencias:
                          "Hallazgos de IA y reglas que requieren revisión humana.",
                        Eventos:
                          "Cronología de recepción de los registros.",
                        Conocimiento:
                          "Guías y políticas versionadas, con recuperación vectorial.",
                        Ajustes:
                          "Configure el proveedor y revise las tarifas.",
                        "Estado y costos":
                          "Dependencias y contabilidad persistente.",
                      } as Record<string, string>
                    )[view]
                  }
                </p>
              </div>
            </div>
          )}
          {error && (
            <p role="alert" className="error">
              {error}
              <ArcButton variant="ghost" onClick={() => setError("")}>
                Cerrar aviso
              </ArcButton>
            </p>
          )}
          {view === "Resumen" && <Dashboard onOpenCve={() => setView("CVE")} />}
          {view === "Incidencias" && (
            <>
              <div hidden={selected !== null}>
                <IncidentList refresh={refresh} onOpen={setSelected} />
              </div>
              {selected && (
                <Incident
                  key={selected}
                  id={selected}
                  refresh={refresh}
                  generationPaused={Boolean(status.generation_paused)}
                  onOpenRelated={setSelected}
                  onBack={() => {
                    const id = selected;
                    setSelected(null);
                    requestAnimationFrame(() =>
                      document
                        .querySelector<HTMLButtonElement>(
                          `[data-report-id="${id}"]`,
                        )
                        ?.focus(),
                    );
                  }}
                />
              )}
            </>
          )}
          {view === "Eventos" && <><EventList refresh={refresh} /><details><summary>Revisión de registros y cobertura</summary><RecordReview refresh={refresh} /></details></>}
          {view === "Conocimiento" && <Knowledge refresh={refresh} />}{" "}
          {view === "Servicios" && <ServiceCatalog api={api} refresh={refresh} />}
          {view === "Análisis" && <AnalysisPanel api={api} refresh={refresh} />}
          {view === "CVE" && <CveTab api={api} refresh={refresh} />}
          {view === "Ajustes" && <><ServiceCatalog api={api} refresh={refresh} /><details className="settings-section"><summary>Proveedor de generación</summary><Settings /></details><details className="settings-section"><summary>Reglas empresariales</summary><BusinessRules /></details></>}
          {view === "Estado y costos" && <Status refresh={refresh} />}
        </main>
        <footer>
          Epiphyllum Sentinel · Demo educativa local · America/Costa_Rica
        </footer>
      </div>
    </div>
  );
}
export function Notifications({refresh, onOpen}: {refresh: number; onOpen: (id: string) => void}) {
  const [items, setItems] = useState<Data[]>([]), [unread, setUnread] = useState(0), [error, setError] = useState("");
  const menu = useRef<HTMLDetailsElement>(null);
  useEffect(() => { let active=true; api("/notifications").then(d => { if(active){setItems(d.items);setUnread(Number(d.unread_count ?? 0));setError("");} }).catch(e => {if(active)setError(e.message);}); return()=>{active=false;}; }, [refresh]);
  useEffect(() => { const close = (e: PointerEvent) => { if(menu.current && !menu.current.contains(e.target as Node)) menu.current.open=false; }; document.addEventListener("pointerdown", close); return()=>document.removeEventListener("pointerdown", close); }, []);
  async function markAllRead() {
    const pending = items.filter(i => !i.read_at);
    for (const item of pending) {
      try { await api(`/notifications/${item.incident_id}/read`, "POST", {}); } catch (e) { setError((e as Error).message); notifyToast("error", "No se pudieron marcar las notificaciones", (e as Error).message); return; }
    }
    if (pending.length) { setItems(current => current.map(i => ({...i, read_at: i.read_at || new Date().toISOString()}))); setUnread(0); notifyToast("success", "Notificaciones marcadas como leídas"); }
  }
  async function open(item: Data) {
    try {
      if (!item.read_at) { await api(`/notifications/${item.incident_id}/read`, "POST", {}); setItems(current=>current.map(i=>i.incident_id===item.incident_id?{...i,read_at:new Date().toISOString()}:i)); setUnread(count=>Math.max(0,count-1)); }
      if(menu.current) menu.current.open=false;
      onOpen(item.incident_id);
    } catch (e) { setError((e as Error).message); notifyToast("error", "No se pudo abrir la notificación", (e as Error).message); }
  }
  return <details ref={menu} className="notification-menu" onKeyDown={e=>{if(e.key==="Escape" && menu.current?.open){menu.current.open=false;menu.current.querySelector<HTMLElement>("summary")?.focus();}}}>
    <summary aria-label={`Notificaciones${unread ? `, ${unread} sin leer` : ", ninguna sin leer"}`} title="Notificaciones">
      <svg aria-hidden="true" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/></svg>
      {unread>0 && <span className="notification-count" aria-hidden="true">{unread>99?"99+":unread}</span>}
    </summary>
    <section className="notification-panel" aria-label="Lista de notificaciones" tabIndex={0}>
      <div className="notification-heading"><h2>Notificaciones</h2><span>{unread} sin leer</span>{unread > 0 && <ArcButton type="button" variant="secondary" size="sm" onClick={() => void markAllRead()}>Marcar todas como leídas</ArcButton>}</div>
      {error && <p role="alert">{error}</p>}
      {!items.length ? <EmptyState title="No hay notificaciones" description="Cuando una incidencia nueva requiera revisión, aparece acá." /> : <ul>{items.map((item, index)=><li key={`${item.incident_id}-${item.opened_at}-${index}`} className={item.read_at?"":"unread"}>
        <ArcButton onClick={()=>void open(item)}><span className="notification-sev" data-severity={item.severity} aria-hidden="true" /><span className="notification-body"><span className="notification-title">{item.title}</span><span className="notification-meta">{item.read_at ? "Leída" : "Sin leer"} · {severity[item.severity] || item.severity} · {time(item.opened_at)}</span><span className="notification-meta">{item.service || "Servicio sin identificar"} · {states[item.analysis_state] || item.analysis_state || "Detección disponible"}</span>{item.summary && <span className="notification-summary">{item.summary}</span>}</span></ArcButton>
      </li>)}</ul>}
      {items.length===100 && <p className="notification-empty">Se muestran las 100 notificaciones más recientes.</p>}
    </section>
  </details>;
}
const eventLabels: Record<string, string> = {
  "auth.failed": "Fallos de autenticación",
  "auth.success": "Accesos exitosos",
  "app.error": "Errores de aplicación",
  "system.notice": "Avisos del sistema",
};
const number = (value: number) =>
  new Intl.NumberFormat(locale()).format(value || 0);
const dollars = (units: number) =>
  new Intl.NumberFormat(locale(), {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(Number(units || 0) / 1e8);
function Dashboard({ onOpenCve }: { onOpenCve: () => void }) {
  const [data, setData] = useState<Data | null>(null),
    [error, setError] = useState(""),
    [notes, setNotes] = useState(""),
    [dirty, setDirty] = useState(false),
    [saving, setSaving] = useState(false),
    [notice, setNotice] = useState("");
  const editing = useRef(false),
    notesVersion = useRef(0),
    request = useRef(0);
  const [cve, setCve] = useState<Data | null>(null);
  const [reportItems, setReportItems] = useState<Data[]>([]);
  const [topFindings, setTopFindings] = useState<Data[]>([]);
  const [allCveFindings, setAllCveFindings] = useState<Data[]>([]);
  const load = useCallback(async () => {
    const seq = ++request.current;
    void api("/cve/services").then((summary: Data) => {if (seq === request.current) setCve(summary);}).catch(() => {});
    void api("/cve/findings?limit=100&offset=0&affects=true").then((d: Data) => {if (seq === request.current) setTopFindings(d.items || []);}).catch(() => {});
    void api("/cve/findings?limit=100&offset=0").then((d: Data) => {if (seq === request.current) setAllCveFindings(d.items || []);}).catch(() => {});
    void api("/reports?limit=50").then((d: Data) => {if (seq === request.current) setReportItems(d.items || []);}).catch(() => {});
    try {
      const next = await api("/dashboard");
      if (seq !== request.current) return;
      setData(next);
      setError("");
      if (!editing.current && next.notes.version >= notesVersion.current) {
        setNotes(next.notes.text);
        notesVersion.current = next.notes.version;
      }
    } catch (e) {
      if (seq === request.current) setError((e as Error).message);
    }
  }, []);
  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => {
      clearInterval(timer);
      request.current++;
    };
  }, [load]);
  async function saveNotes(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setNotice("");
    try {
      const saved = await api("/dashboard/notes", "PUT", {
        text: notes,
        expected_version: notesVersion.current,
      });
      notesVersion.current = saved.version;
      editing.current = false;
      setDirty(false);
      setNotice("Notas guardadas.");
      notifyToast("success", "Notas guardadas");
      void load();
    } catch (e) {
      setNotice((e as Error).message);
      notifyToast("error", "No se pudieron guardar las notas", (e as Error).message);
    } finally {
      setSaving(false);
    }
  }
  if (!data)
    return (
      <section className="dashboard">
        <p role={error ? "alert" : "status"}>
          {error || "Cargando métricas de la demo…"}
        </p>
        {error && <ArcButton onClick={() => void load()}>Reintentar</ArcButton>}
      </section>
    );
  const total = data.totals,
    budget = data.budget;
  const timelineEvents = (data.timeline || []).map((p: Data) => Number(p.events));
  const timelineLabels = (data.timeline || []).map((p: Data) =>
    new Date(p.hour).toLocaleTimeString("es-CR", {
      timeZone: "America/Costa_Rica",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }),
  );
  const last6 = timelineEvents.slice(-6).reduce((a: number, b: number) => a + b, 0);
  const prev6 = timelineEvents
    .slice(-12, -6)
    .reduce((a: number, b: number) => a + b, 0);
  const eventsChange =
    prev6 > 0
      ? `${last6 >= prev6 ? "+" : "−"}${Math.abs(Math.round(((last6 - prev6) / prev6) * 100))}% (6 h)`
      : undefined;
  const SEVERITY_COLORS: Record<string, string> = {
    critical: "#e5484d",
    high: "#f76b15",
    medium: "#ffb224",
    low: "#46a758",
    informational: "#8b9bab",
  };
  const severityData = (data.severity || [])
    .filter((r: Data) => Number(r.count) > 0)
    .map((r: Data) => ({
      key: String(r.severity),
      label: severity[r.severity] || String(r.severity),
      value: Number(r.count),
      color: SEVERITY_COLORS[r.severity],
    }));
  const spentUsd = Number(budget.spent_units) / 1e8,
    reservedUsd = Number(budget.reserved_units) / 1e8,
    budgetLimitUsd = Number(budget.limit_units) / 1e8;
  return (
    <section className="dashboard" aria-label="Dashboard de la demo">
      <div className="dashboard-toolbar">
        <p>Logs cargados · {number(total.runs)} lotes</p>
        <div>
          <small>
            Actualizado{" "}
            {new Date(data.updated_at).toLocaleTimeString("es-CR", {
              timeZone: "America/Costa_Rica",
            })}
          </small>
          <ArcButton variant="secondary" onClick={() => void load()}>
            Actualizar dashboard
          </ArcButton>
        </div>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <RecordReview summaryOnly refresh={0} />
      <div className="dashboard-metrics">
        <article className="kpi-spark">
          <Sparkline
            label="Eventos normalizados"
            value={number(total.events)}
            change={eventsChange}
            data={timelineEvents.length > 1 ? timelineEvents : [0, 0]}
            labels={timelineLabels}
            tone="accent"
            area
          />
          <small>Registros de las fuentes configuradas · últimas 24 h</small>
        </article>
        <MetricCard
          label="Incidencias detectadas"
          value={Number(total.incidents)}
          context="Hallazgos de reglas deterministas y revisión IA"
        />
        <MetricCard
          label="Prioridad alta o crítica"
          value={Number(total.priority_incidents)}
          context={
            total.incidents
              ? `${Math.round((Number(total.priority_incidents) / Math.max(1, Number(total.incidents))) * 100)}% del total · requieren revisión humana`
              : "Requieren revisión humana"
          }
        />
        <article className="kpi-static">
          <span className="kpi-static-label">Costo de los logs cargados</span>
          <strong className="kpi-static-value">{dollars(Number(data.active_cost.spent_units))}</strong>
          <small>Reservado {dollars(Number(data.active_cost.reserved_units))} · sesión actual</small>
        </article>
      </div>
      {(() => {
        // UI-ARC-05 (puntos 9, 10 y 11): todo se calcula en el cliente desde
        // GET /reports (opened_at, severity, service), que es lo que la API
        // sí devuelve; /dashboard no trae incidencias por día ni por servicio.
        const dayKey = (d: Date) => d.toLocaleDateString("en-CA", { timeZone: "America/Costa_Rica" });
        const days: { key: string; label: string; axis: string }[] = [];
        for (let i = 6; i >= 0; i--) { const d = new Date(Date.now() - i * 86400000); days.push({ key: dayKey(d), label: d.toLocaleDateString("es-CR", { timeZone: "America/Costa_Rica", weekday: "long", day: "numeric", month: "long" }), axis: d.toLocaleDateString("es-CR", { timeZone: "America/Costa_Rica", weekday: "short" }) }); }
        const perDay = days.map(d => reportItems.filter(r => dayKey(new Date(r.opened_at)) === d.key).length);
        const sevKeys = ["critical", "high", "medium", "low"] as const;
        // UI-ARC-06 (puntos 1, 4 y 5): Streamgraph y Waffle REALES de Arc
        // (instalados del registry @uiarc en esta ronda). El stream recibe
        // la serie por días con ceros — o por horas si todo cae en un día
        // (ver streamData más abajo) — para que el eje se lea entero.
        const streamSeries = sevKeys.filter(k => reportItems.some(r => r.severity === k)).map(k => ({ key: k, label: severity[k], color: SEVERITY_COLORS[k] }));
        // UI-ARC-08: el stream trabaja sobre la VENTANA ACTIVA, no sobre
        // el día completo. Con las incidencias reales de Allan (13 entre
        // 01:12 y 01:38) la serie de 24 cubetas horarias de UI-ARC-06
        // dejaba una sola cubeta con datos: espiga al borde izquierdo,
        // ancho útil medido 7,5 %. buildStreamWindow elige ventana y
        // granularidad desde los datos (5 min / 1 h / 1 día), suaviza si
        // el flujo queda angosto y declara la ventana en el epígrafe.
        const weekKeys = new Set(days.map(d => d.key));
        const streamWindow = buildStreamWindow(reportItems.filter(r => weekKeys.has(dayKey(new Date(r.opened_at)))).map(r => ({ opened_at: r.opened_at as unknown, severity: r.severity as unknown })), sevKeys);
        const streamData = streamWindow?.data ?? [];
        const streamCaption = streamWindow?.caption ?? "Por día y severidad";
        const streamCategory = streamWindow?.granularity === "days" ? "Día" : streamWindow?.granularity === "hours" ? "Hora" : "Ventana";
        const byService = new Map<string, number>();
        reportItems.forEach(r => byService.set(String(r.service || "No identificado"), (byService.get(String(r.service || "No identificado")) || 0) + 1));
        const waffleData = [...byService.entries()].sort((a, b) => b[1] - a[1]).map(([label, value], i) => ({ key: label, label, value, color: WAFFLE_COLORS[i % WAFFLE_COLORS.length] }));
        const totalWeek = perDay.reduce((a, b) => a + b, 0);
        return <div className="charts06-grid">
          <section className="dashboard-panel" aria-label="Incidencias por día">
            <div className="panel-heading"><h2>Incidencias por día</h2><span>Últimos 7 días · promedio {totalWeek ? (totalWeek / 7).toFixed(1) : "0"} por día</span></div>
            {totalWeek ? <BarChart label="Incidencias por día" period="Últimos 7 días" averageLabel="Promedio diario" valueLabel="Incidencias" categoryLabel="Día" showAverage height={190} data={days.map((d, i) => ({ key: d.key, label: d.label, axisLabel: d.axis, value: perDay[i] }))} /> : <EmptyState title="Sin incidencias en los últimos 7 días" description="El gráfico de barras aparece cuando se registran incidencias en la semana." />}
          </section>
          <section className="dashboard-panel" aria-label="Flujo de incidencias por severidad">
            <div className="panel-heading"><h2>Flujo de incidencias</h2><span>{streamCaption}</span></div>
            {streamSeries.length && streamData.length ? <StreamPanel data={streamData} series={streamSeries} categoryLabel={streamCategory} /> : <EmptyState title="Sin flujo para mostrar" description="Todavía no hay incidencias por severidad en los últimos 7 días." />}
          </section>
          <section className="dashboard-panel charts06-waffle" aria-label="Incidencias por servicio">
            <div className="panel-heading"><h2>¿Qué servicio trae más incidencias?</h2><span>Sobre el total registrado · cada celda = 1 %</span></div>
            {waffleData.length ? <WafflePanel data={waffleData} /> : <EmptyState title="Sin incidencias por servicio" description="Cuando haya incidencias, cada celda del waffle es 1 % del total." />}
          </section>
        </div>;
      })()}
      {cve && (() => {
        const items: Data[] = cve.services || cve.items || [];
        const monitored = items.filter((s: Data) => s.software_product);
        const affecting = items.reduce((sum: number, s: Data) => sum + (s.check?.state === "completed" ? Number(s.check.affecting_count || 0) : 0), 0);
        const lastCheck = items.map((s: Data) => s.check?.checked_at).filter(Boolean).sort().at(-1);
        const worst = [...items].filter((s: Data) => s.check?.state === "completed").sort((a: Data, b: Data) => Number(b.check.affecting_count || 0) - Number(a.check.affecting_count || 0))[0];
        return <section className="dashboard-panel cve-dash-panel" data-alert={affecting > 0 || undefined} aria-label="Resumen de vulnerabilidades CVE">
          <div className="panel-heading"><h2>Vulnerabilidades (CVE)</h2><span>{cve.daily_enabled ? "Worker diario activado" : "Worker diario desactivado"}</span></div>
          <div className="cve-dash-top">
          <div className="cve-dash-metrics">
            <div><span>Servicios monitoreados</span><strong>{monitored.length} de {items.length}</strong></div>
            <div><span>CVE que te afectan</span><strong>{number(affecting)}</strong></div>
            <div><span>Último chequeo</span><strong>{lastCheck ? new Date(lastCheck).toLocaleString("es-CR", {timeZone: "America/Costa_Rica"}) : "Nunca"}</strong></div>
          </div>
          <div className="cve-dash-gauge">
            <Gauge
              label="Servicios monitoreados"
              value={items.length ? Math.round((monitored.length / items.length) * 100) : 0}
              detail={`${monitored.length} de ${items.length} con software declarado o detectado`}
              thresholds={[
                { from: 0, tone: "danger", label: "Sin cobertura" },
                { from: 1, tone: "warning", label: "Cobertura parcial" },
                { from: 100, tone: "success", label: "Cobertura total" },
              ]}
            />
          </div>
          {/* UI-ARC-06 (punto 6): el donut de CVE también vive en el panel
              del dashboard, completo dentro de la card con su leyenda.
              UI-ARC-07 (punto 3): misma cascada que la pestaña CVE —
              (1) que afectan por severidad, (2) todos los hallazgos por
              severidad, (3) sin hallazgos: cobertura de comprobación
              (comprobados vs pendientes, centro «N de M»). Antes con 0
              que afectan el donut desaparecía del panel. */}
          {(() => {
            const sevOf = (list: Data[]) => ["critical", "high", "medium", "low", "unknown"].map(k => ({ key: k, label: k === "unknown" ? "Sin puntaje" : severity[k], value: list.filter((f: Data) => (f.severity || "unknown") === k).length, color: SEVERITY_COLORS[k] || "#8b9bab" })).filter(d => d.value > 0);
            const affectsData = sevOf(topFindings), allData = sevOf(allCveFindings);
            const checkedN = items.filter((s: Data) => s.check?.state === "completed").length;
            const coverageData = [{key: "checked", label: "Comprobados", value: checkedN, color: "#46a758"}, {key: "pending", label: "Pendientes de comprobar", value: items.length - checkedN, color: "#5b6b7d"}].filter(d => d.value > 0);
            const donutData = affectsData.length ? affectsData : allData.length ? allData : coverageData;
            if (!donutData.length) return null;
            const isCoverage = !affectsData.length && !allData.length;
            return <div className="cve-dash-donut"><DonutChart label={affectsData.length ? "CVE que te afectan por severidad" : allData.length ? "Hallazgos CVE por severidad" : "Cobertura de comprobación CVE"} data={donutData} totalLabel={affectsData.length ? "Te afectan" : allData.length ? "Hallazgos" : "Servicios"} size={168} {...(isCoverage ? {formatValue: (v: number) => v === items.length && items.length > 0 ? `${checkedN} de ${items.length}` : String(v)} : {})} /></div>;
          })()}
          </div>
          {affecting > 0 && worst ? <p><strong>{worst.name}</strong> es el servicio más expuesto: {number(Number(worst.check.affecting_count || 0))} CVE lo afectan ({worst.software_product} {worst.software_version}). Revisá el detalle y preguntale a la IA desde la pestaña CVE.</p> : <p className="muted">{monitored.length ? "Ningún CVE afecta hoy a los servicios monitoreados." : "Todavía no hay servicios con software declarado o detectado por banner."}</p>}
          {monitored.length > 0 && <div className="table-wrap cve-dash-services" tabIndex={0} role="region" aria-label="Servicios monitoreados y su exposición CVE">
            <ArcTable caption="Servicios monitoreados y su exposición CVE" rows={monitored.slice(0, 6)} rowKey="id" emptyMessage="Sin servicios monitoreados" columns={[
              {key: "name", label: "Servicio", render: (_v, s2) => <>{s2.name}<small>{s2.software_origin === "mcp" ? "Versión vía MCP (version.json)" : s2.software_origin === "banner" ? "Detectado vía banner (sin confirmar)" : "Declarado por el operador"}</small></>},
              {key: "software_product", label: "Software", render: (_v, s2) => <>{s2.software_product} {s2.software_version}</>},
              {key: "affecting", label: "Te afectan", render: (_v, s2) => s2.check?.state === "completed" ? <strong className={Number(s2.check.affecting_count || 0) > 0 ? "cve-affecting-count" : undefined}>{number(Number(s2.check.affecting_count || 0))}</strong> : <span className="muted">{s2.check?.state === "failed" ? "Chequeo fallido" : "Sin chequeo"}</span>},
              {key: "checked", label: "Último chequeo", render: (_v, s2) => s2.check?.checked_at ? new Date(s2.check.checked_at).toLocaleString("es-CR", {timeZone: "America/Costa_Rica", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false}) : "—"},
            ]} />
          </div>}
          {topFindings.length > 0 && <div className="cve-dash-findings">
            <h3>Hallazgos más graves que te afectan</h3>
            <ul>{topFindings.slice(0, 3).map((f: Data) => <li key={f.id}><Badge value={f.severity} /><strong>{f.cve_id}</strong><span>{f.service_name} · {f.product} {f.version}</span>{f.fixed_version && <span className="muted">corregido en {f.fixed_version}</span>}</li>)}</ul>
          </div>}
          <div className="cve-dash-actions"><ArcButton variant="secondary" onClick={onOpenCve}>Abrir pestaña CVE</ArcButton></div>
        </section>;
      })()}
      <div className="dashboard-grid">
        <section className="dashboard-panel activity-panel">
          <div className="panel-heading">
            <h2>Actividad de eventos</h2>
            <span>Recepción por hora</span>
          </div>
          <LineChart
            label="Eventos recibidos por hora"
            data={(data.timeline || []).map((p: Data, i: number) => ({
              key: String(p.hour),
              label: new Date(p.hour).toLocaleString("es-CR", {
                timeZone: "America/Costa_Rica",
                weekday: "short",
                hour: "2-digit",
                minute: "2-digit",
                hour12: false,
              }),
              axisLabel:
                i % 4 === 0
                  ? new Date(p.hour).toLocaleTimeString("es-CR", {
                      timeZone: "America/Costa_Rica",
                      hour: "2-digit",
                      minute: "2-digit",
                      hour12: false,
                    })
                  : undefined,
              values: { events: Number(p.events) },
            }))}
            series={[{ key: "events", label: "Eventos" }]}
            height={230}
          />
        </section>
        <section className="dashboard-panel severity-panel">
          <div className="panel-heading">
            <h2>Incidencias por severidad</h2>
          </div>
          {severityData.length ? (
            <DonutChart
              label="Incidencias por severidad"
              data={severityData}
              totalLabel="Incidencias"
              size={210}
            />
          ) : (
            <EmptyState title="Todavía no hay incidencias" description="Cuando una regla o la IA detecte algo, la distribución por severidad aparece acá." />
          )}
          <p className="muted">
            La severidad conserva su fuente: regla o propuesta IA con evidencia.
          </p>
        </section>
        <section className="dashboard-panel slope-panel">
          <div className="panel-heading">
            <h2>De eventos a incidencias</h2>
            <span>Por tipo de evento</span>
          </div>
          {(() => {
            const rows = [...(data.by_event_type || [])].sort((a: Data, b: Data) => Number(b.events) - Number(a.events));
            const max = Math.max(1, ...rows.map((r: Data) => Number(r.events)));
            return rows.length ? <div className="conversion-list">
              <div className="conversion-legend" aria-hidden="true"><span><i className="conversion-swatch events" />Eventos</span><span><i className="conversion-swatch incidents" />Incidencias</span><span className="muted">misma escala</span></div>
              {rows.map((r: Data) => <div className="conversion-row" key={String(r.event_type)}>
                <span className="conversion-label">{eventLabels[r.event_type] || String(r.event_type)}</span>
                <div className="conversion-bars" aria-hidden="true">
                  <div className="conversion-track"><span className="conversion-fill events" style={{width: `${Math.max(1.5, (Number(r.events) / max) * 100)}%`}} /></div>
                  <div className="conversion-track"><span className="conversion-fill incidents" style={{width: `${Math.max(1.5, (Number(r.incidents) / max) * 100)}%`}} /></div>
                </div>
                <span className="conversion-nums"><strong>{number(Number(r.events))}</strong> eventos → <strong>{number(Number(r.incidents))}</strong> incidencias{Number(r.events) > 0 ? <> · {Math.round((Number(r.incidents) / Number(r.events)) * 100)}%</> : null}</span>
              </div>)}
            </div> : <EmptyState title="Todavía no hay eventos por tipo" description="La conversión de eventos a incidencias aparece cuando ingresan registros." />;
          })()}
          <p className="muted">
            Cuántos eventos de cada tipo terminaron agrupados en una incidencia.
          </p>
        </section>
        <section className="dashboard-panel event-costs">
          <div className="panel-heading">
            <h2>Costos por tipo de evento</h2>
            <span>USD · sesión actual</span>
          </div>
          <p className="muted">
            Esta tabla atribuye explicaciones al disparador normalizado, sin duplicar evidencia.
            La revisión primaria se concilia en Cobertura y el total incluye ambos recorridos.
          </p>
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Tabla de costos por tipo de evento">
            <ArcTable caption="Costos por tipo de evento" rows={data.by_event_type as Data[]} rowKey="event_type" emptyMessage="Sin costos registrados" columns={[
              {key: "event_type", label: "Tipo de evento", render: (_v, row) => <>{eventLabels[row.event_type]}<small>{row.event_type}</small></>},
              {key: "events", label: "Eventos", render: (_v, row) => number(row.events)},
              {key: "incidents", label: "Incidencias", render: (_v, row) => number(row.incidents)},
              {key: "calls", label: "Envíos", render: (_v, row) => number(row.calls)},
              {key: "spent_units", label: "Costo", render: (_v, row) => <>{dollars(row.spent_units)}{row.estimated && <small>Cargo conservador</small>}</>},
            ]} />
          </div>
          {budget.cap_enabled ? <UsageMeter
            label="Presupuesto de la sesión"
            unit="USD"
            decimals={2}
            warnAt={0.8}
            segments={[
              { id: "spent", label: "Gastado", value: spentUsd },
              { id: "reserved", label: "Reservado", value: reservedUsd },
            ]}
            limit={budgetLimitUsd}
          /> : <section className="session-spend" aria-label="Gasto de la sesión sin tope">
            <div className="panel-heading"><div><h3>Gasto de la sesión</h3><p className="muted">Sin tope monetario configurado.</p></div></div>
            <div className="session-spend-values">
              <div><span>Gastado</span><strong>{dollars(budget.spent_units)}</strong></div>
              <div><span>Reservado</span><strong>{dollars(budget.reserved_units)}</strong></div>
              <div><span>Total contabilizado</span><strong>{dollars(Number(budget.spent_units || 0) + Number(budget.reserved_units || 0))}</strong></div>
            </div>
            <p className="muted">No hay límite ni sobrepaso: el total es solo referencia contable. Si activás el tope en Ajustes, se aplicará a las solicitudes nuevas.</p>
          </section>}
          <p className="muted">
            Los conteos corresponden a los logs cargados. El registro conserva
            todo el gasto de la sesión, incluidas las pruebas retiradas.
          </p>
        </section>
        <section className="dashboard-panel quick-notes">
          <div className="panel-heading">
            <h2>Notas rápidas</h2>
            {dirty && <span>Sin guardar</span>}
          </div>
          <p className="muted">
            Apuntes administrativos de la demo. No se envían a la IA.
          </p>
          <form onSubmit={saveNotes}>
            <ArcTextarea
              label="Notas rápidas de la demo"
              id="dashboard-notes"
              rows={7}
              maxLength={4000}
              value={notes}
              placeholder="Anota pendientes, verificaciones o puntos para la presentación…"
              onChange={(e) => {
                editing.current = true;
                setNotes(e.target.value);
                setDirty(true);
                setNotice("");
              }}
            />
            <div className="notes-actions">
              <small>{notes.length}/4000</small>
              <ArcButton disabled={saving || !dirty}>
                {saving ? "Guardando…" : "Guardar notas"}
              </ArcButton>
            </div>
            <p role="status" className="notes-status">
              {notice}
            </p>
          </form>
        </section>
      </div>
    </section>
  );
}
function IncidentList({
  refresh,
  onOpen,
}: {
  refresh: number;
  onOpen: (id: string) => void;
}) {
  const [items, setItems] = useState<Data[]>([]),
    [runs, setRuns] = useState<string[]>([]),
    [batches, setBatches] = useState<Data[]>([]),
    [service, setService] = useState(""),
    [severityFilter, setSeverityFilter] = useState(""),
    [rule, setRule] = useState(""),
    [analysis, setAnalysis] = useState(""),
    [run, setRun] = useState(""),
    [size, setSize] = useState(10),
    [cursors, setCursors] = useState<(string | null)[]>([null]),
    [next, setNext] = useState<string | null>(null),
    [total, setTotal] = useState(0),
    [loading, setLoading] = useState(false),
    [error, setError] = useState(""),
    [changed, setChanged] = useState(false);
  const request = useRef(0),
    previousRefresh = useRef(refresh);
  const load = useCallback(
    async (cursor: string | null) => {
      const seq = ++request.current;
      setLoading(true);
      setError("");
      try {
        const q = new URLSearchParams({ limit: String(size) });
        if (cursor) q.set("cursor", cursor);
        if (severityFilter) q.set("severity", severityFilter);
        if (rule) q.set("rule_id", rule);
        if (analysis) q.set("analysis_state", analysis);
        if (run) q.set("run_id", run);
        if (service) q.set("service_id", service);
        const res = await api("/reports?" + q);
        if (seq !== request.current) return;
        setItems(res.items);
        setRuns(res.available_runs || []);
        setBatches(res.available_batches || []);
        setTotal(res.total_count);
        setNext(res.next_cursor);
        setChanged(false);
      } catch (e) {
        if (seq === request.current) setError((e as Error).message);
      } finally {
        if (seq === request.current) setLoading(false);
      }
    },
    [size, severityFilter, rule, analysis, run, service],
  );
  useEffect(() => {
    setCursors([null]);
    void load(null);
    return () => {
      request.current++;
    };
  }, [load]);
  useEffect(() => {
    if (previousRefresh.current !== refresh) {
      previousRefresh.current = refresh;
      setChanged(true);
    }
  }, [refresh]);
  const page = cursors.length;
  return (
    <section className="incident-list-page" aria-label="Listado de incidencias">
      <div className="list-heading">
        <h2>Listado de incidencias</h2>
        <ArcButton
          variant="secondary"
          disabled={loading}
          onClick={() => {
            setCursors([null]);
            void load(null);
          }}
        >
          Actualizar listado
        </ArcButton>
      </div>
      {changed && (
        <p className="notice">
          Hay cambios en el historial. Actualiza el listado para consultarlos.
        </p>
      )}
      <div className="filters">
        <ServicePicker api={api} value={service} onChange={setService} refresh={refresh} />
        <ArcSelect label="Severidad" value={severityFilter || "__all__"} onValueChange={(v) => setSeverityFilter(v === "__all__" ? "" : v)} options={[{value: "__all__", label: "Todas"}, ...Object.entries(severity).map(([k, v]) => ({value: k, label: v}))]} />
        <ArcSelect label="Regla" value={rule || "__all__"} onValueChange={(v) => setRule(v === "__all__" ? "" : v)} options={[{value: "__all__", label: "Todas"}, ...["R1", "R2", "R3", "R4", "AI"].map((r) => ({value: r, label: r}))]} />
        <ArcSelect label="Análisis" value={analysis || "__all__"} onValueChange={(v) => setAnalysis(v === "__all__" ? "" : v)} options={[{value: "__all__", label: "Todos"}, ...["pending", "succeeded", "cached", "blocked_config", "unknown", "skipped_budget"].map((k) => ({value: k, label: states[k]}))]} />
        <ArcSelect label="Lote de logs" value={run || "__all__"} onValueChange={(v) => setRun(v === "__all__" ? "" : v)} options={[{value: "__all__", label: "Todos"}, ...runs.map((id) => ({value: id, label: `${time(batches.find(b=>b.id===id)?.received_at)} · ${batches.find(b=>b.id===id)?.downloaded ? "Descargados" : "Generados"} · ${batches.find(b=>b.id===id)?.events ?? "—"} eventos`}))]} />
        {(service || severityFilter || rule || analysis || run) && (
          <ArcButton
            type="button"
            className="secondary clear-filters"
            onClick={() => {
              setService("");
              setSeverityFilter("");
              setRule("");
              setAnalysis("");
              setRun("");
            }}
          >
            Limpiar filtros
          </ArcButton>
        )}
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className="incident-column-head" aria-hidden="true">
        <span>Incidencia y regla</span>
        <span>Evidencia</span>
        <span>Servicio</span>
        <span>Recepción</span>
        <span>Análisis</span>
      </div>
      <div className="incident-rows" aria-busy={loading}>
        {!items.length && !loading ? (
          <EmptyState title="No hay incidencias con estos filtros" description="Probá ampliar el rango o quitar algún filtro para ver más resultados." />
        ) : (
          items.map((item) => (
            <ArcButton
              className="report-row incident-row"
              key={item.id}
              data-report-id={item.id}
              data-severity={item.severity}
              onClick={() => onOpen(item.id)}
            >
              <div className="incident-description">
                <div>
                  <Badge value={item.severity} />
                  <span>
                    {item.rule_id} / v{item.rule_version}
                  </span>
                  <ClassificationBadge value={item.classification} />
                </div>
                <h3>{item.title}</h3>
              </div>
              <p className="incident-evidence">
                {number(item.evidence_count)} elementos de evidencia · {item.detection_origin === "ai" ? "Hallazgo IA" : item.detection_origin === "both" ? "Regla e IA" : "Regla"}
                <span>Versión {item.evidence_version}</span>
              </p>
              <p className="incident-service"><span className="visually-hidden">Servicio: </span>{item.service || "No identificado"}</p>
              <time dateTime={item.opened_at}>{time(item.opened_at)}</time>
              <div className="incident-analysis">
                {item.analysis ? (
                  <>
                    <Badge value={item.analysis.state} />
                    <small>
                      {item.analysis.origin === "live" ? `${item.analysis.provider} / API` : item.analysis.origin || "Estado del gateway"}
                    </small>
                  </>
                ) : (
                  <small>{item.rule_id === "R4" ? "Explicación local" : "Sin generación IA"}</small>
                )}
              </div>
            </ArcButton>
          ))
        )}
      </div>
      <nav className="pagination" aria-label="Paginación de incidencias">
        <ArcSelect label="Por página" value={String(size)} onValueChange={(v) => setSize(Number(v))} options={[{value:"10",label:"10"},{value:"25",label:"25"},{value:"50",label:"50"}]} />
        <span role="status">
          {total
            ? `${(page - 1) * size + 1}–${Math.min((page - 1) * size + items.length, total)} de ${number(total)}`
            : "0 incidencias"}{" "}
          · Página {page}
        </span>
        <div>
          <ArcButton
            variant="secondary"
            disabled={loading || page === 1}
            onClick={() => {
              const previous = cursors.slice(0, -1);
              setCursors(previous);
              void load(previous.at(-1) ?? null);
            }}
          >
            Anterior
          </ArcButton>
          <ArcButton
            variant="secondary"
            disabled={loading || !next}
            onClick={() => {
              if (next) {
                setCursors([...cursors, next]);
                void load(next);
              }
            }}
          >
            Siguiente
          </ArcButton>
        </div>
      </nav>
    </section>
  );
}

function Incident({
  id,
  refresh,
  generationPaused,
  onBack,
  onOpenRelated,
}: {
  id: string;
  refresh: number;
  generationPaused: boolean;
  onBack: () => void;
  onOpenRelated: (id: string) => void;
}) {
  const [detail, setDetail] = useState<Data | null>(null),
    [tab, setTab] = useState("Resumen"),
    [revision, setRevision] = useState(""),
    [error, setError] = useState(""),
    [observation, setObservation] = useState("");
  const titleRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (detail?.id) titleRef.current?.focus();
  }, [detail?.id]);
  useEffect(() => {
    api("/reports/" + id)
      .then(setDetail)
      .catch((e) => setError(e.message));
  }, [id, refresh]);
  if (!detail)
    return (
      <section className="detail">
        <ArcButton variant="ghost" className="back" onClick={onBack}>
          ← Volver a incidencias
        </ArcButton>
        <p role="status">{error || "Cargando evidencia…"}</p>
      </section>
    );
  const latest = detail.analysis_revisions?.find((j: Data) => j.id === revision) || detail.analysis_revisions?.find((j: Data) => j.analysis) || detail.analysis_revisions?.[0];
  const response = latest?.analysis?.response;
  async function followup(action: string) {
    try {
      await api(`/reports/${id}/followup`, "POST", {action, observation});
      setObservation("");
      setDetail(await api(`/reports/${id}`));
      notifyToast("success", "Seguimiento actualizado", action === "closed" ? "La incidencia quedó cerrada; el historial se conserva." : action === "acknowledged" ? "La incidencia quedó reconocida." : action === "reopened" ? "La incidencia volvió a abrirse." : "La observación quedó registrada.");
    } catch (e) { setError((e as Error).message); notifyToast("error", "No se pudo actualizar el seguimiento", (e as Error).message); }
  }
  return (
    <section
      className={"detail " + (tab === "Chat" ? "is-chat" : "")}
      aria-label="Incidencia seleccionada"
      data-incident-id={id}
    >
      <ArcButton className="back link" onClick={onBack}>
        ← Volver a incidencias
      </ArcButton>
      <div className="detail-header">
        <div>
          <Badge value={detail.severity} />
          <span className="muted">
            {detail.rule_id} / versión {detail.rule_version}
          </span>
        </div>
        <h1 ref={titleRef} tabIndex={-1}>
          {detail.title}
        </h1>
        <p>
          Servicio: {detail.service || "No identificado"} · {detail.evidence_count} registros de evidencia · Evidencia v{detail.evidence_version}
        </p>
        <small>Recibido {time(detail.opened_at)}</small>
      </div>
      <ArcTabs value={tab} onValueChange={(v) => setTab(v)}>
        <ArcTabsList className="tabs" aria-label="Detalle de incidencia">
          {["Resumen", "Evidencia", "Chat"].map((t) => (
            <ArcTabsTrigger key={t} value={t}>
              {t}
            </ArcTabsTrigger>
          ))}
        </ArcTabsList>
        <ArcTabsContent
          value={tab}
          forceMount
          className={"tab-content " + (tab === "Chat" ? "chat-content" : "")}
        >
        {(tab === "Resumen" || tab === "Evidencia") && (
          <div className="incident-reading">
            {detail.detection_origin === "ai" && detail.related_incident_ids?.length > 0 && <p className="muted">{detail.related_incident_ids.map((related: string) => <ArcButton key={related} variant="ghost" onClick={() => onOpenRelated(related)}>Ver agrupación e historial anterior</ArcButton>)}</p>}
            {(() => {
              const items: { id: string; at: string; actor: string; title: string; meta?: string }[] = [
                {
                  id: "opened",
                  at: detail.opened_at,
                  actor: "Detección",
                  title: `Incidencia abierta: ${detail.title}`,
                  meta: `${detail.rule_id || "Revisión primaria"} · severidad ${severity[detail.severity] || detail.severity}`,
                },
              ];
              if (detail.last_match_at && detail.last_match_at !== detail.opened_at)
                items.push({
                  id: "last-match",
                  at: detail.last_match_at,
                  actor: "Detección",
                  title: "Última coincidencia registrada",
                  meta: "La detección siguió agrupando eventos en esta incidencia",
                });
              (detail.analysis_revisions || []).forEach((j: Data) =>
                items.push({
                  id: `job-${j.id}`,
                  at: j.created_at,
                  actor: "Análisis IA",
                  title: j.state === "completed" ? "Análisis generado" : `Análisis ${states[j.state] || j.state}`,
                  meta: `${j.provider || ""} ${j.model || ""} · evidencia v${j.evidence_version}`,
                }),
              );
              (detail.findings || []).forEach((f: Data) =>
                items.push({
                  id: `finding-${f.id}`,
                  at: f.created_at,
                  actor: "Revisión primaria",
                  title: f.payload?.title || "Hallazgo validado con evidencia citada",
                  meta: `Severidad propuesta ${severity[f.severity] || f.severity}`,
                }),
              );
              (detail.followup_actions || []).forEach((a: Data) =>
                items.push({
                  id: `action-${a.id}`,
                  at: a.created_at,
                  actor: "Operador",
                  title: a.action || "Acción de seguimiento",
                  meta: a.observation || undefined,
                }),
              );
              return (
                <section className="incident-timeline" aria-label="Línea de tiempo de la incidencia">
                  <h3>Línea de tiempo</h3>
                  <Timeline
                    events={items}
                    now={Date.now()}
                    label="Línea de tiempo de la incidencia"
                    timeZone="America/Costa_Rica"
                    locale="es-CR"
                  />
                </section>
              );
            })()}
            {detail.findings?.length > 0 && <section className="incident-interpretation" aria-label="Hallazgos validados">
              <h2>Análisis generado por IA</h2>
              <p>Severidad propuesta por IA, sustentada en citas. No confirma compromiso.</p>
              {detail.findings.map((f: Data) => <article key={f.id} className="event">
                <div className="origin"><Badge value={f.origin} /><Badge value={f.severity} /><span>{f.job.provider} / {f.job.model}</span></div>
                <h3>{f.payload.title}</h3><p>{f.payload.reason}</p>
                {new Set((f.snapshot?.assigned || []).map((s: Data) => s.record_id)).size > 1 && <p className="notice">Análisis histórico generado con varios registros: sus hipótesis pueden incluir contexto de otros eventos. Iniciá una nueva revisión para obtener un análisis aislado.</p>}
                <h4>Evidencia literal</h4>{f.payload.evidence.filter((c: Data) => f.segments?.some((s: Data) => s.id === c.segment_id)).map((c: Data, i: number) => {
                  const text = f.segments.find((s: Data) => s.id === c.segment_id)?.text;
                  return <details key={`${c.segment_id}-${i}`}><summary>Ver cita {i + 1} · segmento <code>{c.segment_id}</code></summary>{c.quote && <pre>{c.quote}</pre>}{text && text !== c.quote && <><p>Texto del segmento</p><pre>{text}</pre></>}</details>;
                })}
                <h4>Incertidumbre y alternativas</h4><ul>{[...f.payload.uncertainty,...f.payload.alternatives].map((t: string,i:number) => <li key={i}>{t}</li>)}</ul>
                <h4>Comprobaciones humanas</h4><ul>{f.payload.human_checks.map((t:string,i:number)=><li key={i}>{t}</li>)}</ul>
                <h4>Fuentes consultadas</h4>
                {f.knowledge_references?.length ? f.knowledge_references.map((ref: Data) => { const source = f.snapshot?.chunks?.find((c: Data) => c.chunk_id === ref.chunk_id && c.revision === ref.version); return <details className="citation" key={ref.chunk_id}><summary>{source?.title || ref.chunk_id} · revisión {ref.version}</summary><blockquote><SafeText value={source?.text || "Fragmento no disponible."} /></blockquote><small>{source?.source}</small></details> }) : <p>No se citaron fuentes de conocimiento.</p>}
                <details><summary>Trazabilidad de revisión</summary><pre>{JSON.stringify({job:f.job.id,primary:f.snapshot.assigned,context:f.snapshot.context,corpus:f.snapshot.corpus_version},null,2)}</pre></details>
              </article>)}
            </section>}
            {detail.detection_origin !== "ai" && <section className="incident-interpretation">
              <h3>{detail.rule_id === "R4" ? "Explicación local por política" : tab === "Evidencia" ? "Hallazgos de la evidencia" : "Resumen de IA"}</h3>
              {detail.analysis_revisions?.length > 1 && <ArcSelect label="Revisión del análisis" value={latest?.id || ""} onValueChange={setRevision} options={detail.analysis_revisions.map((j: Data) => ({value: j.id, label: `Evidencia v${j.evidence_version} · ${states[j.state] || j.state} · ${j.model}`}))} />}
              {response ? <>
                <div className="origin"><Badge value={latest.analysis.origin} /><span>{latest.provider} / {latest.model} · Evidencia v{latest.evidence_version}{latest.evidence_version < detail.evidence_version ? " · Hay evidencia posterior" : ""}</span></div>
                <p className="analysis-lead">{response.summary}</p>
                <p>{response.explanation}</p>
                {tab === "Evidencia" && <p className="notice">Se reutiliza este análisis almacenado. {latest.snapshot?.events?.length || 0} eventos seleccionados; {latest.snapshot?.omitted_count || 0} omitidos. Abrir esta pestaña no realiza llamadas.</p>}
                <ResponseParts response={response} snapshot={latest.snapshot} />
                {latest.snapshot?.observability && <ObservabilityBlock observability={latest.snapshot.observability} />}
              </> : <p>{detail.rule_id === "R4" ? "El literal hostil se conserva como dato no confiable. No es una orden ni prueba de compromiso; se recomienda revisar su contexto. R4 nunca usa un generador, tampoco en Chat." : latest ? `${states[latest.state] || latest.state}: ${reviewReason(latest.reason) || "Esperando turno del gateway compartido."}` : "Análisis pendiente de disponibilidad del corpus. Los hechos ya están guardados."}</p>}
              {latest && <Trace job={latest} />}
            </section>}
            {tab === "Resumen" && detail.detection_origin !== "ai" && <details className="detector-details"><summary>Datos del detector</summary>
              <h3>Hechos deterministas</h3>
              <p>La regla {detail.rule_id} alcanzó su condición: {detail.deterministic_reason.threshold} coincidencias en {detail.deterministic_reason.window_seconds} segundos de recepción.</p>
              <p>Servicio: {detail.service || "No identificado"} · {detail.evidence_count} registros de evidencia · Evidencia v{detail.evidence_version} · Run <code>{detail.run_id}</code></p>
              <p className="notice">Este patrón no confirma compromiso. La severidad la establece el detector, no la IA.</p>
              {detail.related_incident_ids?.map((related: string) => <p key={related}>Incidencia relacionada: <code>{related}</code></p>)}
            </details>}
            {tab === "Resumen" && (
      <section aria-label="Seguimiento humano">
        <h2>Seguimiento humano</h2>
        <p>Estado: {({open:"Abierta", acknowledged:"Reconocida", closed:"Cerrada"} as Data)[detail.followup_state]}. Las decisiones no ejecutan acciones sobre sistemas.</p>
        {error && <p role="alert">{error}</p>}
        <ArcTextarea label="Observación" value={observation} maxLength={2000} onChange={e => setObservation(e.target.value)} />
        <ArcButton onClick={() => void followup("observation")} disabled={!observation.trim()}>Guardar observación</ArcButton>{" "}
        {detail.followup_state === "open" && <ArcButton onClick={() => void followup("acknowledged")}>Reconocer incidencia</ArcButton>}
        {detail.followup_state === "acknowledged" && <ArcButton onClick={() => void followup("closed")}>Cerrar incidencia</ArcButton>}
        {detail.followup_state === "closed" && <ArcButton onClick={() => void followup("reopened")}>Reabrir incidencia</ArcButton>}
        <ul>{detail.followup_actions?.map((a: Data) => <li key={a.id}>{time(a.created_at)} · {({acknowledged:"Reconocida", closed:"Cerrada", reopened:"Reabierta", observation:"Observación"} as Data)[a.action] || a.action} {a.observation && <SafeText value={a.observation} />}</li>)}</ul>
      </section>
            )}
            {tab === "Evidencia" && <EventList incident={id} refresh={refresh} />}
          </div>
        )}
        {tab === "Chat" && (
          <Chat
            id={id}
            evidenceVersion={detail.evidence_version}
            refresh={refresh}
            generationPaused={generationPaused}
          />
        )}
        </ArcTabsContent>
      </ArcTabs>
    </section>
  );
}
export function ObservabilityBlock({observability}: {observability: Data}) {
  const profiles: Data[] = observability.profiles || [];
  const classifications: Data[] = observability.classifications || [];
  if (!profiles.length && !classifications.length) return null;
  return <section className="observability-block" aria-labelledby="obs-block-heading">
    <h4 id="obs-block-heading">Límites y evidencia del servicio</h4>
    {profiles.map((p: Data) => <p key={p.service_id} className="muted">Perfil de límites: huella <code>{String(p.fingerprint || "").slice(0, 12)}</code> · {p.active_entries_total ?? (p.entries || []).filter((e: Data) => e.status === "active").length} entradas activas congeladas en este análisis.{Number(p.omitted_entries || 0) > 0 ? ` Resumen acotado: se incluyeron ${(p.relevant_entries || []).length} entradas relevantes para esta evidencia y se omitieron ${p.omitted_entries} por tamaño; el perfil completo está en Editar servicio.` : ""} Cambiar el perfil no reinterpreta este historial.</p>)}
    {classifications.map((c: Data) => <div className="fact" key={c.event_id}>
      <ClassificationBadge value={c.classification} />{" "}
      <small>Evento <code>{String(c.event_id).slice(0, 8)}</code></small>
      <dl>
        <dt>Hecho observado</dt><dd>{c.http ? `${c.http.method || ""} ${c.http.normalized_path || c.http.raw_target || ""} · estado ${c.http.status ?? "—"}` : "Sin evidencia HTTP estructurada"}</dd>
        {c.http?.raw_target && <><dt>Target original</dt><dd><code>{c.http.raw_target}</code></dd></>}
        {c.http?.origin === "server_normalized_only" && <><dt>Normalización</dt><dd>La fuente solo aporta la ruta ya normalizada por Nginx; el target original no consta y no se reconstruye.</dd></>}
        {c.http?.origin === "raw_only" && <><dt>Normalización</dt><dd>La fuente solo aporta el target crudo (raw_only): la clasificación se hizo contra ese target y Sentinel no conoce la normalización real del servidor.</dd></>}
        <dt>Motivo de la clasificación</dt><dd>{c.reason?.detail || "—"}</dd>
        <dt>Impacto confirmado</dt><dd>No: un intento observado y la respuesta del servidor no confirman acceso al recurso. Se requiere evidencia adicional (registro de aplicación, canario o cambio de estructura) y verificación humana.</dd>
      </dl>
    </div>)}
    {!classifications.length && <p className="muted">Los eventos de esta incidencia no tienen clasificación de límites persistida (anterior a la migración 0028 o sin evidencia HTTP).</p>}
  </section>;
}
export function ResponseParts({
  response,
  snapshot,
}: {
  response: Data;
  snapshot: Data;
}) {
  const facts = response.facts || response.evidence?.map((e: Data) => ({text:e.claim, event_ids:[e.event_id]})) || [];
  return (
    <>
      {facts.length > 0 && (
        <>
          <h4>Hallazgos con evidencia</h4>
          {facts.map((f: Data, i: number) => (
            <div className="fact" key={i}>
              {f.text}{" "}
              <small>
                {f.event_ids.map((id: string) => (
                  <details key={id} className="citation">
                    <summary>Evento {id}</summary>
                    <SafeText
                      value={
                        snapshot?.events?.find((e: Data) => e.id === id) ||
                        "Evento no disponible"
                      }
                    />
                  </details>
                ))}
              </small>
            </div>
          ))}
        </>
      )}
      {response.hypotheses?.length > 0 && (
        <>
          <h4>Hipótesis</h4>
          <ul>
            {response.hypotheses.map((h: Data, i: number) => (
              <li key={i}>
                {h.text} <span className="muted">Confianza {({low:"baja",medium:"media",high:"alta"} as Record<string,string>)[h.confidence] || h.confidence}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      <h4>Incertidumbre</h4>
      <ul>
        {response.uncertainty?.map((t: string, i: number) => (
          <li key={i}>{t}</li>
        ))}
      </ul>
      <h4>Comprobaciones humanas</h4>
      <ul>
        {(response.human_checks || response.recommendations || []).map(
          (t: string, i: number) => (
            <li key={i}>{t}</li>
          ),
        )}
      </ul>
      <h4>Fuentes del snapshot</h4>
      {response.knowledge_references?.length ? (
        response.knowledge_references.map((r: Data) => {
          const c = snapshot?.chunks?.find(
            (c: Data) => c.chunk_id === r.chunk_id && c.revision === r.version,
          );
          return (
            <details className="citation" key={r.chunk_id}>
              <summary>
                {c?.title || r.chunk_id} · revisión {r.version}
              </summary>
              <blockquote>
                <SafeText value={c?.text || "Fragmento no disponible."} />
              </blockquote>
              <small>
                {c?.source} · {c?.scope === "service" ? "Específico del servicio" : "General"} · <code>{r.chunk_id}</code>
              </small>
            </details>
          );
        })
      ) : (
        <p>
          No se recuperaron fuentes pertinentes. Falta conocimiento suficiente
          para fundamentar la respuesta.
        </p>
      )}
    </>
  );
}
function Trace({ job }: { job: Data }) {
  return (
    <details className="trace">
      <summary>Cómo se construyó esta respuesta</summary>
      <dl>
        <dt>Estado</dt>
        <dd>
          {states[job.state] || job.state} {job.reason}
        </dd>
        <dt>Modelo y perfil</dt>
        <dd>
          {job.model}, perfil v{job.provider_profile_version}
        </dd>
        <dt>Evidencia</dt>
        <dd>
          v{job.evidence_version}, {job.snapshot?.events?.length || 0} eventos,{" "}
          {job.snapshot?.omitted_count || 0} omitidos
        </dd>
        <dt>Corpus y políticas</dt>
        <dd>
          <code>{job.corpus_version}</code>
          <br />
          <code>{job.policy_version}</code>
        </dd>
        {job.snapshot?.observability && <><dt>Límites del servicio</dt><dd>{(job.snapshot.observability.profiles || []).map((p: Data) => <span key={p.service_id}>Huella <code>{String(p.fingerprint || "").slice(0, 12)}</code> · {p.active_entries_total ?? (p.entries || []).filter((e: Data) => e.status === "active").length} entradas activas{Number(p.omitted_entries || 0) > 0 ? ` (${p.omitted_entries} omitidas en el resumen)` : ""}<br /></span>)}{(job.snapshot.observability.classifications || []).length} clasificaciones deterministas en la evidencia</dd><dt>Conocimiento por ámbito</dt><dd>{(job.snapshot.chunks || []).filter((c: Data) => c.scope === "service").length} fragmentos específicos del servicio · {(job.snapshot.chunks || []).filter((c: Data) => c.scope !== "service").length} generales</dd></>}
        <dt>Prompt y redacción</dt>
        <dd>
          v{job.prompt_version} / v{job.redaction_version}
        </dd>
      </dl>
      <p>Ruta {job.route?.level === "deep" ? "profunda" : "estándar"} · router v{job.route?.router_version || "histórico"}: {job.route?.reason || "Ruta anterior al router"}</p>
      <p>Origen {job.analysis?.origin || "sin respuesta"} · {job.provider} / {job.model}</p>
      {job.attempts?.map((a: Data) => <p key={a.id}>Tokens de entrada/salida: {a.input_tokens ?? "sin uso fiable"} / {a.output_tokens ?? "sin uso fiable"}. USD {(a.accounted_units / 100000000).toFixed(8)} {a.usage_estimated ? "estimado conservador" : "contabilizado"}. Estado {states[a.state] || a.state}. Modelo informado: {a.provider_metadata?.model || "no informado"}</p>)}
      <details>
        <summary>Datos exactos incluidos</summary>
        <pre>{JSON.stringify(job.snapshot, null, 2)}</pre>
      </details>
    </details>
  );
}
export function EventList({ incident, refresh }: { incident?: string; refresh: number }) {
  const [events,setEvents]=useState<Data[]>([]),[more,setMore]=useState<string|null>(null),[error,setError]=useState(""),[total,setTotal]=useState(0);
  const [detailEvent,setDetailEvent]=useState<Data|null>(null);
  const [page,setPage]=useState(0),[cursors,setCursors]=useState<(string | undefined)[]>([undefined]);
  const [serviceId,setServiceId]=useState(""),[eventType,setEventType]=useState(""),[sourceKind,setSourceKind]=useState(""),[size,setSize]=useState(10);
  const [eventsToast,setEventsToast]=useState(false); const lastRefresh=useRef(refresh); const toastTimer=useRef<ReturnType<typeof setTimeout> | null>(null);
  const path=incident ? `/reports/${incident}/evidence` : "/events";
  const load=useCallback(async(cursor?:string)=>{try {const q=new URLSearchParams({limit:String(size)}); if(cursor)q.set("cursor",cursor); if(!incident){if(serviceId)q.set("service_id",serviceId); if(eventType)q.set("event_type",eventType); if(sourceKind)q.set("source",sourceKind);} const r=await api(path+"?"+q);setEvents(r.items);setMore(r.next_cursor);setTotal(r.total_count ?? 0);setError("");}catch(e){setError((e as Error).message);}},[path,size,incident,serviceId,eventType,sourceKind]);
  useEffect(()=>{setPage(0);setCursors([undefined]);},[path,serviceId,eventType,sourceKind,size]);
  useEffect(()=>{void load(cursors[page]);},[load,cursors,page]);
  // UI-ARC-05 (punto 2): ante eventos nuevos la tabla se actualiza sola
  // (sin banner blanco que empuje el layout) y avisa con un toast flotante
  // discreto que se despide solo a los 5 s.
  useEffect(()=>{if(lastRefresh.current!==refresh){lastRefresh.current=refresh;setPage(0);setCursors([undefined]);void load(undefined);setEventsToast(true);notifyToast("info","Eventos actualizados","La tabla de eventos se actualizó automáticamente.");if(toastTimer.current)clearTimeout(toastTimer.current);toastTimer.current=setTimeout(()=>setEventsToast(false),5000);}},[refresh]); // eslint-disable-line react-hooks/exhaustive-deps
  const filtersActive = Boolean(serviceId || eventType || sourceKind);
  return <div className="event-list">{eventsToast&&<div className="events-toast" role="status"><span>Hay eventos nuevos. La tabla se actualizó automáticamente.</span><ArcButton type="button" variant="ghost" size="sm" onClick={()=>setEventsToast(false)}>Cerrar aviso</ArcButton></div>}{error&&<p role="alert">{error}</p>}
    {!incident && <div className="filters event-filters">
      <ServicePicker api={api} value={serviceId} onChange={setServiceId} refresh={refresh} />
      <ArcSelect label="Tipo de evento" value={eventType || "__all__"} onValueChange={v=>setEventType(v === "__all__" ? "" : v)} options={[{value:"__all__",label:"Todos"},{value:"auth.failed",label:"Fallos de autenticación"},{value:"auth.success",label:"Accesos aceptados"},{value:"app.error",label:"Errores de aplicación"},{value:"system.notice",label:"Avisos del sistema"}]} />
      <ArcSelect label="Origen" value={sourceKind || "__all__"} onValueChange={v=>setSourceKind(v === "__all__" ? "" : v)} options={[{value:"__all__",label:"Todos"},{value:"auth",label:"Autenticación"},{value:"app",label:"Aplicación"},{value:"system",label:"Sistema"}]} />
      {filtersActive && <ArcButton type="button" className="secondary clear-filters" onClick={()=>{setServiceId("");setEventType("");setSourceKind("");}}>Limpiar filtros</ArcButton>}
    </div>}
    <div className="table-scroll"><ArcTable caption="Eventos normalizados" rows={events} rowKey="id" emptyMessage="Sin eventos" columns={[
      {key: "event_time", label: "Hora", render: (_v, e) => time(e.event_time)},
      {key: "event_type", label: "Tipo", render: (_v, e) => <>{e.event_type}<ClassificationBadge value={e.classification} /></>},
      {key: "level", label: "Nivel", render: (_v, e) => <span className="event-level" data-level={e.level}>{e.level}</span>},
      {key: "service", label: "Servicio", render: (_v, e) => e.service || "—"},
      {key: "message", label: "Mensaje", render: (_v, e) => <span className="record-preview">{e.message}</span>},
      {key: "detail", label: "Detalle", render: (_v, e) => <ArcButton type="button" variant="ghost" aria-expanded={detailEvent?.id === e.id} onClick={() => setDetailEvent(detailEvent?.id === e.id ? null : e)}>Ver</ArcButton>},
    ]} /></div>
    {detailEvent && <>
      {/* UI-ARC-06 (punto 9): el detalle ya no se abre ABAJO de la tabla
          (había que scrollear hasta el fondo para verlo). Ahora es un
          drawer lateral fijo, visible sin scroll, con fondo que cierra
          al hacer click afuera y botón de cierre. */}
      <button type="button" className="event-drawer-backdrop" aria-label="Cerrar detalle del evento" onClick={() => setDetailEvent(null)} />
      <aside className="event-drawer" aria-label="Detalle del evento">
      <div className="event-detail-heading"><h3>Detalle del evento</h3><ArcButton type="button" variant="secondary" onClick={() => setDetailEvent(null)}>Cerrar detalle</ArcButton></div>
      <dl>{(() => { const e = detailEvent; return <><dt>ID interno</dt><dd><code>{e.id}</code></dd><dt>ID del registro</dt><dd><code>{e.external_event_id || e.record_id || "—"}</code></dd><dt>Hora de recepción</dt><dd>{time(e.ingested_at)}</dd><dt>Fuente</dt><dd>{e.source}</dd><dt>Incluido en análisis</dt><dd>{e.selected_for_analysis ? "Sí" : "No"}</dd><dt>Formato</dt><dd>{e.parser || "sentinel-json"}</dd>{e.classification && <><dt>Clasificación</dt><dd>{CLASSIFICATION_LABELS[e.classification] || e.classification}{e.classification_reason?.detail ? ` — ${e.classification_reason.detail}` : ""}</dd></>}{e.http && <><dt>Solicitud HTTP</dt><dd>{e.http.method} · estado {e.http.status ?? "—"}</dd><dt>Ruta normalizada</dt><dd><code>{e.http.normalized_path || "no consta"}</code></dd><dt>Target original</dt><dd>{e.http.raw_target ? <code>{e.http.raw_target}</code> : "no consta en el registro"}</dd>{e.http.origin === "server_normalized_only" && <><dt>Nota de normalización</dt><dd>La fuente solo aporta la ruta ya normalizada por Nginx ($uri): el target original no existe en el log y no se reconstruye con certeza.</dd></>}{e.http.origin === "raw_only" && <><dt>Nota de normalización</dt><dd>La fuente solo aporta el target crudo (raw_only): la clasificación usa ese target y Sentinel no conoce la normalización real del servidor.</dd></>}</>}<dt>Mensaje</dt><dd><SafeText value={e.message} /></dd></>; })()}</dl>
      </aside>
    </>}
    {!events.length&&<EmptyState title={filtersActive ? "No hay eventos con estos filtros" : "No hay eventos disponibles"} description={filtersActive ? "Probá quitar algún filtro para ver más resultados." : "Cuando una fuente ingiera registros, los eventos aparecen acá."} />}
    <nav className="pagination" aria-label="Páginas de eventos"><ArcSelect label="Por página" value={String(size)} onValueChange={v=>setSize(Number(v))} options={[{value:"10",label:"10"},{value:"25",label:"25"},{value:"50",label:"50"}]} /><span>{total ? `${total} eventos · ` : ""}Página {page+1} · ordenados por recepción, del más reciente al más antiguo</span><ArcButton disabled={page===0} onClick={()=>setPage(p=>p-1)}>Anterior</ArcButton><ArcButton disabled={!more} onClick={()=>{if(more){setCursors(c=>[...c.slice(0,page+1),more]);setPage(p=>p+1);}}}>Siguiente</ArcButton></nav>
  </div>;
}
export function Chat({
  id,
  evidenceVersion,
  refresh,
  generationPaused = false,
}: {
  id: string;
  evidenceVersion: number;
  refresh: number;
  generationPaused?: boolean;
}) {
  const [messages, setMessages] = useState<Data[]>([]),
    [q, setQ] = useState(""),
    [sending, setSending] = useState(false),
    [deep, setDeep] = useState(false),
    [chatActive, setChatActive] = useState(true),
    [error, setError] = useState("");
  const key = useRef(crypto.randomUUID());
  const messageList = useRef<HTMLDivElement>(null);
  const followBottom = useRef(true);
  const visitor = useRef(crypto.randomUUID());
  useEffect(() => {
    let lastInteraction = Date.now(), present = false;
    const markActive = () => { lastInteraction = Date.now(); if (!present) sync(); };
    const sync = () => {
      const active = !document.hidden && Date.now() - lastInteraction < 120000;
      setChatActive(active);
      if (active) {
        present = true;
        void api(`/reports/${id}/chat-presence`, "POST", {visitor_id: visitor.current}).catch(() => setError("No se pudo activar el chat. Comprobá la conexión."));
      } else if (present) {
        present = false;
        void fetch(`/api/v1/reports/${id}/chat-presence/${visitor.current}`, {method:"DELETE", headers:{"X-CSRF-Token":csrf}, keepalive:true}).catch(() => {});
      }
    };
    ["pointerdown", "keydown", "mousemove", "touchstart"].forEach(event => document.addEventListener(event, markActive, {passive:true}));
    document.addEventListener("visibilitychange", sync);
    sync();
    const timer = setInterval(sync, 10000);
    return () => {
      clearInterval(timer);
      ["pointerdown", "keydown", "mousemove", "touchstart"].forEach(event => document.removeEventListener(event, markActive));
      document.removeEventListener("visibilitychange", sync);
      void fetch(`/api/v1/reports/${id}/chat-presence/${visitor.current}`, {method:"DELETE", headers:{"X-CSRF-Token":csrf}, keepalive:true}).catch(() => {});
    };
  }, [id]);
  const load = useCallback(async () => {
    const all: Data[]=[];let cursor="";
    do {const r=await api("/reports/"+id+"/conversation?limit=100"+(cursor?"&cursor="+encodeURIComponent(cursor):""));all.push(...r.items);cursor=r.next_cursor || "";} while(cursor);
    setMessages(all);
  },[id]);
  useEffect(() => {
    void load().catch((e) => setError(e.message));
  }, [load, refresh]);
  const hasPending = messages.some((m) => m.role === "user" && ["pending", "preparing", "reserved", "in_flight"].includes(m.job?.state));
  useEffect(() => {
    if (!hasPending) return;
    const timer = setInterval(() => { void load().catch((e) => setError(e.message)); }, 3000);
    return () => clearInterval(timer);
  }, [hasPending, load]);
  useEffect(() => {
    if (followBottom.current && messageList.current)
      messageList.current.scrollTop = messageList.current.scrollHeight;
  }, [messages.at(-1)?.id]);
  async function send(e: React.FormEvent) {
    e.preventDefault();
    setSending(true);
    setError("");
    followBottom.current = true;
    try {
      await api("/reports/" + id + "/messages", "POST", {
        question: q,
        deep,
        idempotency_key: key.current,
      });
      key.current = crypto.randomUUID();
      setQ("");
      await load();
    } catch (e) {
      setError((e as Error).message);
      notifyToast("error", "No se pudo enviar la pregunta", (e as Error).message);
    } finally {
      setSending(false);
    }
  }
  return (
    <div className="conversation">
      <div className="conversation-context">
        <span>Conversación con evidencia</span>
        <small>Hilo persistente de esta incidencia · fuentes verificables</small>
      </div>
      <div
        className="messages"
        aria-live="polite"
        ref={messageList}
        onScroll={() => {
          const el = messageList.current;
          if (el)
            followBottom.current =
              el.scrollHeight - el.scrollTop - el.clientHeight < 80;
        }}
      >
        {!messages.length && (
          <div className="conversation-empty">
            <Flower />
            <h3>¿Qué quieres aclarar?</h3>
            <p>
              Contrasta los hechos de esta incidencia con sus guías y fuentes.
            </p>
          </div>
        )}
        {messages.map((m) => (
          <React.Fragment key={m.id}>
          <article className={"message " + m.role}>
            <div className="message-label">
              <b>
                {m.role === "user" ? (
                  "Tu pregunta"
                ) : (
                  <>
                    <Flower />
                    Sentinel <Badge value={messages.find((u) => u.id === m.reply_to)?.job?.analysis?.origin || "sin origen informado"} />
                  </>
                )}
              </b>
              <small>
                Evidencia v{m.evidence_version}
                {m.evidence_version < evidenceVersion
                  ? " · Hay evidencia posterior"
                  : ""}
              </small>
            </div>
            {m.role === "user" ? (
              <>
                <p>{m.content.question}</p>
                <div className="message-meta">
                  <Badge value={m.state} />
                  {m.job && <Trace job={m.job} />}
                </div>

              </>
            ) : (
              <>
                <p>{m.content.answer}</p>
                <details className="response-support">
                  <summary>Evidencia, hipótesis y fuentes</summary>
                  <ResponseParts
                    response={m.content}
                    snapshot={
                      messages.find(
                        (u) => u.role === "user" && u.id === m.reply_to,
                      )?.job?.snapshot
                    }
                  />
                </details>
              </>
            )}
          </article>
          {m.role === "user" && m.job && ["pending", "preparing", "reserved", "in_flight"].includes(m.job.state) && <article className="message assistant chat-pending" role="status" aria-live="polite">
            <div className="message-label"><b><Flower /> Sentinel</b></div>
            <div className="chat-activity">{(chatActive || m.job.state === "in_flight") && <span className="review-spinner" aria-hidden="true"/>}<span>{!chatActive && m.job.state !== "in_flight" ? "Chat en pausa por inactividad. Volvé a interactuar para continuar." : m.job.state === "pending" ? (m.job.reason === "rate_limit_wait" ? "Esperando disponibilidad de la API…" : m.job.reason === "circuit_open" ? "El gateway pausó 60 s por respuestas inválidas o ambiguas; no es una caída de red ni falta de cuota." : "Tu pregunta está en cola…") : "Preparando respuesta…"}</span></div>
          </article>}
          {m.role === "user" && m.job && ["failed", "unknown", "blocked_config", "skipped_budget"].includes(m.job.state) && <article className="message assistant chat-error" role="alert"><div className="message-label"><b><Flower /> Sentinel</b></div><p>{m.job.state === "unknown" ? "No se pudo confirmar la respuesta de la API. La solicitud no se repetirá automáticamente." : m.job.reason === "generation_paused" ? "La generación está pausada. Esta pregunta no se envió a la API." : m.job.reason === "session_limit_reached" ? "Se alcanzó el límite de gasto de la sesión. Podés cambiarlo en Ajustes y enviar una pregunta nueva." : m.job.state === "failed" ? "La API no devolvió una respuesta válida. Podés volver a enviar tu pregunta." : "No se pudo preparar la respuesta. Revisá la configuración de la API."}</p></article>}
          </React.Fragment>
        ))}
      </div>
      <div className="conversation-compose">
        <div className="suggestions" aria-label="Preguntas sugeridas">
          {[
            "¿Por qué se disparó?",
            "¿Qué explicación benigna existe?",
            "¿Qué guía respalda esto?",
            "¿Qué datos faltan?",
          ].map((suggestion) => (
            <ArcButton
              variant="secondary"
              key={suggestion}
              onClick={() => {
                setQ(suggestion);
                key.current = crypto.randomUUID();
              }}
            >
              {suggestion}
            </ArcButton>
          ))}
        </div>
        <form onSubmit={send} className="chat-form">
          <ArcTextarea
            label="Pregunta sobre esta incidencia"
            id="question"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              key.current = crypto.randomUUID();
            }}
            maxLength={2000}
            required
            rows={2}
            placeholder="Pregunta sobre los hechos, las hipótesis o las fuentes…"
          />
          <div className="switch-row"><span>Análisis profundo</span><ToggleSwitch label="Análisis profundo" checked={deep} onChange={next => {setDeep(next); key.current=crypto.randomUUID();}} /></div>
          <div>
            <small>{q.length}/2000</small>
            <ArcButton disabled={sending || !q.trim() || generationPaused}>
              <span>Enviar pregunta</span>
              <svg
                width="17"
                height="17"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                aria-hidden="true"
              >
                <path d="M12 19V5M5 12l7-7 7 7" />
              </svg>
            </ArcButton>
          </div>
          {generationPaused && <p className="notice">La IA está pausada. Activá la generación para enviar preguntas.</p>}
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
        </form>
        <small className="conversation-disclaimer">
          Verifica las fuentes; una respuesta no confirma una
          intrusión.
        </small>
      </div>
    </div>
  );
}
export function Knowledge({ refresh }: { refresh: number }) {
  const [data, setData] = useState<Data>({ items: [], builds: [] }),
    [selected, setSelected] = useState<Data | null>(null),
    [text, setText] = useState(""),
    [policy, setPolicy] = useState(""),
    [title, setTitle] = useState(""),
    [kind, setKind] = useState("guide"),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [excluded, setExcluded] = useState<string[]>([]),
    [revisions, setRevisions] = useState<Data[]>([]);
  const [documentPage,setDocumentPage]=useState(0);
  const [buildPage,setBuildPage]=useState(0); const [buildPageSize,setBuildPageSize]=useState(10); const [buildState,setBuildState]=useState("");
  const [editorOpen,setEditorOpen]=useState(false);
  const [docService,setDocService]=useState("");
  const [serviceFilter,setServiceFilter]=useState("");
  const [serviceNames,setServiceNames]=useState<Record<string,string>>({});
      const load = useCallback(async () => {
    let cursor: string | null = null; const items: Data[] = []; let response: Data;
    const seen = new Set<string>();
    do { response = await api("/knowledge?limit=100" + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "")); items.push(...response.items); cursor = response.next_cursor; if (cursor && seen.has(cursor)) throw new Error("No se pudo recorrer el catálogo de conocimiento."); if (cursor) seen.add(cursor); } while (cursor);
    setData({...response!, items});
    try { const s = await api("/services?limit=100&state=all"); const map: Record<string,string>={}; (s.items||[]).forEach((item:Data)=>{map[item.id]=item.name;}); setServiceNames(map); } catch { /* nombres opcionales */ }
  }, []);
  useEffect(() => {
    void load().catch((e) => setError(e.message));
  }, [refresh, load]);
  function edit(d: Data | null) {
    setRevisions([]);
    if (d)
      void api("/knowledge/" + d.id).then((r) => setRevisions(r.revisions));
    setSelected(d);
    setDocService(d?.service_id || "");
    setEditorOpen(true);
    setTitle(d?.title || "");
    setKind(d?.kind || "guide");
    setText(d?.text || "");
    setPolicy(
      d?.metadata?.policy ? JSON.stringify(d.metadata.policy, null, 2) : "",
    );
    setError("");
    setNotice("");
  }
  async function run(fn: () => Promise<unknown>, message: string) {
    setBusy(true);
    setError("");
    try {
      await fn();
      await load();
      setNotice(message);
      notifyToast("success", "Conocimiento actualizado", message);
    } catch (e) {
      setError((e as Error).message);
      notifyToast("error", "No se pudo actualizar el conocimiento", (e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function save(e: React.FormEvent) {
    e.preventDefault();
    let savedOk = false;
    await run(async () => {
      const p = kind === "decision_rule" ? JSON.parse(policy) : null;
      const r = await api(
        selected ? `/knowledge/${selected.id}/draft` : "/knowledge",
        selected ? "PUT" : "POST",
        selected
          ? { expected_version: selected.revision, text, policy: p, service_id: docService || null }
          : {
              title,
              kind,
              text,
              source: "Corpus educativo local revisado por operador",
              license: "CC0-1.0",
              policy: p,
              service_id: docService || null,
            },
      );
      setSelected({
        ...selected,
        id: r.id,
        revision: r.revision,
        title,
        kind,
        metadata: { policy: p },
        text,
      });
      savedOk = true;
    }, "Borrador guardado. Prepare una versión para indexarlo.");
    if (savedOk) setEditorOpen(false);
  }
  const filteredItems = data.items.filter((d: Data) => !serviceFilter || d.service_id === serviceFilter);
  const filteredBuilds = data.builds.filter((b: Data) => !buildState || b.state === buildState);
  return (
    <>
      <div className="knowledge-status">
        <p>
          Corpus activo{" "}
          <code>
            {data.active?.active_corpus_id || "Preparando versión inicial…"}
          </code>
          <br />
          Versión de activación {data.active?.version || 0}
        </p>
        <ArcButton
          disabled={
            busy || data.builds.some((b: Data) => b.state === "building")
          }
          onClick={() =>
            void run(
              () =>
                api("/knowledge/builds", "POST", {
                  manifest: data.items
                    .filter((d: Data) => !excluded.includes(d.id))
                    .map((d: Data) => ({
                      document_id: d.id,
                      revision: d.revision,
                    })),
                  idempotency_key: crypto.randomUUID(),
                }),
              "Versión enviada a indexación local; aún no está activa.",
            )
          }
        >
          Preparar versión
        </ArcButton>
      </div>
      {notice && (
        <p role="status" className="notice">
          {notice}
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <section className="knowledge-list">
          <div className="list-heading">
            <h2>Documentos</h2>
            <ArcButton onClick={() => edit(null)}>
              Nuevo documento
            </ArcButton>
          </div>
          <div className="filters">
            <ServicePicker api={api} label="Filtrar por servicio" value={serviceFilter} onChange={(v)=>{setServiceFilter(v); setDocumentPage(0);}} refresh={refresh} />
            {serviceFilter && <ArcButton type="button" className="secondary clear-filters" onClick={()=>setServiceFilter("")}>Limpiar filtro</ArcButton>}
          </div>
          <div className="table-scroll"><ArcTable caption="Documentos de conocimiento" rows={filteredItems.slice(documentPage*10, documentPage*10+10) as Data[]} rowKey="id" emptyMessage="Sin documentos" columns={[
            {key: "include", label: "Incluir", render: (_v, d) => <ArcCheckbox aria-label={"Incluir " + d.title + " en la próxima versión"} checked={!excluded.includes(d.id)} onCheckedChange={next => setExcluded(next ? excluded.filter(id => id !== d.id) : [...excluded, d.id])} />},
            {key: "title", label: "Documento", render: (_v, d) => <ArcButton variant="ghost" onClick={() => edit(d)}>{d.title}</ArcButton>},
            {key: "kind", label: "Tipo", render: (_v, d) => ({guide: "Guía", rule_explanation: "Explicación", decision_rule: "Política"} as Data)[d.kind] || d.kind},
            {key: "service_id", label: "Ámbito", render: (_v, d) => d.service_id ? <span className="status-pill" data-state="active">{serviceNames[d.service_id] || "Servicio"}</span> : <span className="status-pill" data-state="inactive">General</span>},
            {key: "revision", label: "Revisión"},
            {key: "state", label: "Estado", render: (_v, d) => <span className="status-pill" data-state={d.state === "ready" ? "active" : d.state === "failed" ? "deleted" : "inactive"}>{states[d.state] || d.state}</span>},
          ]} /></div>
          {!filteredItems.length && <EmptyState title="No hay documentos con este filtro" description="Probá con otra búsqueda o subí un documento nuevo." />}
          <nav className="pagination" aria-label="Páginas de conocimiento"><ArcButton disabled={documentPage===0} onClick={()=>setDocumentPage(p=>p-1)}>Anterior</ArcButton><span>Página {documentPage+1} de {Math.max(1,Math.ceil(filteredItems.length/10))}</span><ArcButton disabled={(documentPage+1)*10>=filteredItems.length} onClick={()=>setDocumentPage(p=>p+1)}>Siguiente</ArcButton></nav>
          <p className="withdraw-note">
            Desmarque un documento para retirarlo de la próxima versión. Su
            historial se conserva.
          </p>
        </section>
      {editorOpen && (
        <ArcDialog open onOpenChange={(open)=>{if (!open) setEditorOpen(false);}}>
        <ArcDialogContent title={selected ? "Editar borrador" : "Crear documento"} className="service-dialog knowledge-dialog">
          <p>
            Guardar crea una revisión nueva. El corpus activo conserva su texto
            anterior.
          </p>
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
          <form onSubmit={save}>
            <ArcInput label="Título" value={title} onChange={(e) => setTitle(e.target.value)} disabled={!!selected} maxLength={240} required />
            <ArcSelect label="Tipo" value={kind} onValueChange={setKind} disabled={!!selected} options={[{value:"guide",label:"Guía"},{value:"rule_explanation",label:"Explicación de regla"},{value:"decision_rule",label:"Política de decisión"}]} />
            <ServicePicker api={api} label="Servicio asociado" emptyLabel="General (sin servicio específico)" value={docService} onChange={setDocService} refresh={refresh} />
            <p className="muted">El conocimiento general aplica a todo. Si elegís un servicio, el documento queda asociado a ese servicio y podés filtrarlo en la lista.</p>
            <ArcTextarea label="Texto del documento" rows={9} value={text} onChange={(e) => setText(e.target.value)} maxLength={32768} required />
            {kind === "decision_rule" && (
              <><ArcTextarea label="Condiciones declarativas JSON"
                  rows={8}
                  value={policy}
                  onChange={(e) => setPolicy(e.target.value)}
                  placeholder={
                    '{"scope":["analysis","chat"],"rule_ids":["R1"],"event_types":[],"data_class":"synthetic","effect":"deny"}'
                  }
                  required
                />
                <small>
                  Solo scope, rule_ids, event_types, data_class y effect. Deny
                  prevalece. R4 no se puede permitir.
                </small></>
            )}
            <div className="service-dialog-actions"><ArcButton type="button" variant="secondary" onClick={()=>setEditorOpen(false)}>Cancelar</ArcButton><ArcButton disabled={busy}>Guardar borrador</ArcButton></div>
          </form>
          {revisions.length > 0 && (
            <details className="trace">
              <summary>Historial de revisiones</summary>
              {revisions.map((r) => (
                <details key={r.revision} className="citation">
                  <summary>
                    Revisión {r.revision} · {states[r.state] || r.state}
                  </summary>
                  <SafeText value={r.text} />
                </details>
              ))}
            </details>
          )}
        </ArcDialogContent>
        </ArcDialog>
      )}
      <section className="versions">
        <h2>Versiones del corpus</h2>
        <p>
          Puede activar o revertir a cualquier versión lista. La activación no
          genera llamadas ni cambia el historial.
        </p>
        <div className="builds-toolbar">
          <ArcSelect label="Estado" value={buildState || "__all__"} onValueChange={v => {setBuildState(v === "__all__" ? "" : v); setBuildPage(0);}} options={[{value:"__all__",label:"Todos"},{value:"ready",label:"Lista"},{value:"building",label:"En construcción"},{value:"failed",label:"Fallida"}]} />
          <ArcSelect label="Por página" value={String(buildPageSize)} onValueChange={v => {setBuildPageSize(Number(v)); setBuildPage(0);}} options={[{value:"10",label:"10"},{value:"25",label:"25"},{value:"50",label:"50"}]} />
          <span>{filteredBuilds.length} versiones</span>
        </div>
        <div className="table-scroll"><ArcTable caption="Versiones del corpus" rows={filteredBuilds.slice(buildPage * buildPageSize, buildPage * buildPageSize + buildPageSize) as Data[]} rowKey="id" emptyMessage="Sin versiones" columns={[
          {key: "id", label: "Versión", render: (_v, b) => <><code title={b.id}>{String(b.id).slice(0, 8)}…</code>{b.embedding_model_revision && <small>{b.embedding_model_revision}</small>}</>},
          {key: "created_at", label: "Creada", render: (_v, b) => time(b.created_at)},
          {key: "state", label: "Estado", render: (_v, b) => <><Badge value={b.state} />{b.reason && <small>{b.reason}</small>}</>},
          {key: "documents", label: "Documentos", render: (_v, b) => b.documents ?? "—"},
          {key: "vectors", label: "Vectores", render: (_v, b) => b.vectors ?? "—"},
          {key: "dimension", label: "Dimensiones", render: (_v, b) => `E5 ${b.dimension}`},
          {key: "action", label: "Acción", render: (_v, b) => b.id === data.active?.active_corpus_id ? <strong>Activa</strong> : b.state === "ready" ? <ArcButton variant="secondary" disabled={busy} onClick={() => void run(() => api("/knowledge/active", "PUT", {corpus_id: b.id, expected_version: data.active.version}), "Versión activada. Las consultas nuevas usarán este corpus y sus políticas.")}>Activar versión</ArcButton> : null},
        ]} /></div>
        {!filteredBuilds.length && <p>{data.builds.length ? "Ninguna versión con ese estado." : "Todavía no hay versiones del corpus."}</p>}
        <nav className="pagination" aria-label="Páginas de versiones del corpus"><ArcButton disabled={buildPage === 0} onClick={() => setBuildPage(p => p - 1)}>Anterior</ArcButton><span>{filteredBuilds.length} versiones · Página {buildPage + 1} de {Math.max(1, Math.ceil(filteredBuilds.length / buildPageSize))}</span><ArcButton disabled={(buildPage + 1) * buildPageSize >= filteredBuilds.length} onClick={() => setBuildPage(p => p + 1)}>Siguiente</ArcButton></nav>
      </section>
    </>
  );
}
function Settings() {
  const [data, setData] = useState<Data | null>(null),
    [spendCap, setSpendCap] = useState<Data | null>(null),
    [limitEnabled, setLimitEnabled] = useState(false),
    [amountUsd, setAmountUsd] = useState("1.00"),
    [savingLimit, setSavingLimit] = useState(false),
    [cveSettings, setCveSettings] = useState<Data | null>(null),
    [cveEnabled, setCveEnabled] = useState(false),
    [savingCve, setSavingCve] = useState(false),
    [form, setForm] = useState<Data>({}),
    [key, setKey] = useState(""),
    [deepKey, setDeepKey] = useState(""),
    [catalog, setCatalog] = useState<ModelCatalog | null>(null),
    [specFields, setSpecFields] = useState<SpecFields>(emptySpecFields()),
    [modelSpecs, setModelSpecs] = useState<Record<string, ModelSpec>>({}),
    [modelDrafts, setModelDrafts] = useState<Record<string, SpecFields>>({}),
    [workspaceId, setWorkspaceId] = useState(""),
    [advancedOpen, setAdvancedOpen] = useState(false),
    [customModel, setCustomModel] = useState(false),
    [deepProfileText, setDeepProfileText] = useState("null"),
    [check, setCheck] = useState<{ result: AiCheckResult; fingerprint: string } | null>(null),
    [checking, setChecking] = useState(false),
    [message, setMessage] = useState(""),
    [error, setError] = useState("");
  useEffect(() => {
    api("/settings/ai")
      .then((d) => {
        setData(d);
        setCatalog(d.catalog ?? null);
        const profile = d.profile ?? {};
        const specs: Record<string, ModelSpec> = profile.models || {};
        const drafts: Record<string, SpecFields> = profile.drafts || {};
        const provider = ["openai", "deepseek", "gemini", "claude", "compatible"].includes(profile.provider) ? profile.provider : "openai";
        const model = profile.model || "";
        setModelSpecs(specs);
        setModelDrafts(drafts);
        setWorkspaceId(profile.workspace_id || "");
        setForm({...profile, provider, base_url: profile.base_url || defaultBase(provider), model, mode: profile.mode === "live" ? "live" : "draft"});
        setSpecFields(specFieldsFrom(specs[model] || drafts[model], provider));
        setDeepProfileText(JSON.stringify(profile.deep_profile || null,null,2));
      })
      .catch((e) => setError(e.message));
    api("/costs")
      .then((costs) => {
        const account = costs.accounts?.find((a: Data) => a.scope === "session" && a.scope_key === costs.session_id);
        if (!account) throw new Error("No se encontró la cuenta de esta sesión.");
        setSpendCap(account);
        setLimitEnabled(account.cap_enabled);
        setAmountUsd((Number(account.limit_units) / 1e8).toFixed(2));
      })
      .catch((e) => setError(e.message));
    api("/settings/cve")
      .then((cve) => { setCveSettings(cve); setCveEnabled(!!cve.enabled); })
      .catch((e) => setError(e.message));
  }, []);
  async function saveCve(e: React.FormEvent) {
    e.preventDefault();
    setSavingCve(true);
    try {
      const saved = await api("/settings/cve", "PUT", {expected_version: cveSettings?.version, enabled: cveEnabled});
      setCveSettings(saved);
      setMessage(cveEnabled ? "Chequeo diario de CVE activado." : "Chequeo diario de CVE desactivado.");
      setError("");
      notifyToast("success", "Detector de CVE actualizado", cveEnabled ? "El chequeo diario queda activado." : "El chequeo diario queda desactivado; la comprobación manual sigue disponible.");
    } catch (e) {
      setError((e as Error).message);
      notifyToast("error", "No se pudo guardar el detector de CVE", (e as Error).message);
    } finally {
      setSavingCve(false);
    }
  }
  async function saveLimit(e: React.FormEvent) {
    e.preventDefault();
    setSavingLimit(true);
    try {
      const saved = await api("/settings/spend-limit", "PUT", {
        expected_version: spendCap?.cap_version,
        enabled: limitEnabled,
        amount_usd: limitEnabled ? amountUsd : undefined,
      });
      setSpendCap(saved);
      setMessage(limitEnabled ? "Límite activado para nuevas solicitudes." : "Límite desactivado; nuevas solicitudes sin tope de sesión.");
      setError("");
      notifyToast(limitEnabled ? "success" : "warning", limitEnabled ? "Límite de gasto activado" : "Límite de gasto desactivado", limitEnabled ? "Se aplicará a las solicitudes nuevas." : "Las solicitudes nuevas no tendrán tope monetario de sesión.");
    } catch (e) {
      setError((e as Error).message);
      notifyToast("error", "No se pudo guardar el límite de gasto", (e as Error).message);
    } finally {
      setSavingLimit(false);
    }
  }
  function chooseModel(id: string) {
    setCustomModel(false);
    setForm((current: Data) => ({...current, model: id}));
    const entry = findCatalogEntry(catalog, form.provider, id);
    if (modelDrafts[id]) setSpecFields(modelDrafts[id]);
    else if (modelSpecs[id]) setSpecFields(specFieldsFrom(modelSpecs[id], form.provider));
    else setSpecFields(specFieldsFrom(entry?.spec, form.provider));
  }
  function collectModels() {
    const models: Record<string, ModelSpec> = {};
    const drafts: Record<string, SpecFields> = {...modelDrafts};
    const candidate = specFromFields(specFields);
    if (form.model) {
      if (specIsValid(candidate, form.provider)) {
        models[form.model] = candidate;
        delete drafts[form.model];
      } else {
        drafts[form.model] = specFields;
        delete models[form.model];
      }
    }
    if (form.deep_model) {
      const entry = findCatalogEntry(catalog, form.provider, form.deep_model);
      const deepSpec = modelSpecs[form.deep_model] || entry?.spec;
      if (deepSpec && specIsValid(deepSpec, form.provider)) models[form.deep_model] = deepSpec;
    }
    return {models, drafts};
  }
  async function persistProfile(mode: "live" | "draft", message: string) {
    let deepProfile;
    try {deepProfile = JSON.parse(deepProfileText);} catch {throw new Error("Revise el JSON del perfil profundo avanzado.");}
    const {models, drafts} = collectModels();
    const d = await api("/settings/ai", "PUT", {
      expected_version: data?.version,
      name: form.name,
      provider: form.provider,
      base_url: form.base_url,
      model: form.model,
      deep_model: form.deep_model || "",
      models,
      drafts,
      deep_profile: deepProfile,
      mode,
      json_mode: form.json_mode,
      workspace_id: form.provider === "claude" ? workspaceId : "",
      api_key: key || undefined,
      deep_api_key: deepKey || undefined,
    });
    setData(d);
    setCatalog(d.catalog ?? catalog);
    setForm({...d.profile, mode: d.profile.mode === "live" ? "live" : "draft"});
    setModelSpecs(d.profile.models || {});
    setModelDrafts(d.profile.drafts || {});
    setWorkspaceId(d.profile.workspace_id || "");
    setSpecFields(specFieldsFrom((d.profile.models || {})[d.profile.model] || (d.profile.drafts || {})[d.profile.model], d.profile.provider));
    setKey("");
    setDeepKey("");
    setCheck(null);
    setMessage(message);
    setError("");
    notifyToast(mode === "live" ? "success" : "warning", mode === "live" ? "Perfil guardado y habilitado" : "Borrador guardado", message);
  }
  async function runCheck() {
    const fingerprint = aiCheckFingerprint({ provider: form.provider, base_url: form.base_url, model: form.model, typedKey: key.length > 0 });
    setChecking(true);
    try {
      const d = await api("/settings/ai/check", "POST", {
        provider: form.provider,
        base_url: form.base_url,
        model: form.model,
        workspace_id: form.provider === "claude" ? workspaceId : "",
        ...(key ? { api_key: key } : {}),
      });
      setCheck({ result: d, fingerprint });
      const view = aiCheckView(d);
      notifyToast(view.tone === "ok" ? "success" : view.tone === "warn" ? "warning" : "error", view.title, view.detail);
    } catch (e) {
      setCheck(null);
      setError((e as Error).message);
      notifyToast("error", "No se pudo probar la conexión", (e as Error).message);
    } finally {
      setChecking(false);
    }
  }
  async function save(e: React.FormEvent) {
    e.preventDefault();
    const candidate = specFromFields(specFields);
    const missing = missingSpecFields(candidate, form.provider);
    if (missing.length) {
      setAdvancedOpen(true);
      setError(`No se puede habilitar: falta ${missing.join(", ")}.`);
      setMessage("");
      notifyToast("warning", "Ficha del modelo incompleta", missing.join(", "));
      return;
    }
    const deepMissing = form.deep_model ? missingSpecFields(modelSpecs[form.deep_model] || findCatalogEntry(catalog, form.provider, form.deep_model)?.spec, form.provider) : [];
    if (form.deep_model && deepMissing.length) {
      setAdvancedOpen(true);
      setError(`No se puede habilitar: falta la ficha del modelo profundo (${deepMissing.join(", ")}).`);
      setMessage("");
      notifyToast("warning", "Ficha del modelo profundo incompleta", deepMissing.join(", "));
      return;
    }
    try {
      await persistProfile("live", "Perfil guardado y habilitado. No se realizó ninguna llamada.");
    } catch (e) {
      setError((e as Error).message);
      notifyToast("error", "No se pudo guardar el perfil", (e as Error).message);
    }
  }
  async function saveDraft() {
    const {models} = collectModels();
    const keepLive = data?.profile?.mode === "live" && !!models[form.model] && (!form.deep_model || !!models[form.deep_model]);
    try {
      await persistProfile(keepLive ? "live" : "draft", keepLive
        ? "Borrador guardado; el perfil live conserva una ficha válida."
        : "Borrador guardado. La generación queda en modo borrador hasta completar la ficha y usar «Guardar y habilitar».");
    } catch (e) {
      setError((e as Error).message);
      notifyToast("error", "No se pudo guardar el borrador", (e as Error).message);
    }
  }
  const checkView = check ? aiCheckView(check.result) : null;
  const checkStale = check !== null && check.fingerprint !== aiCheckFingerprint({ provider: form.provider, base_url: form.base_url, model: form.model, typedKey: key.length > 0 });
  const catalogEntry = findCatalogEntry(catalog, form.provider, form.model);
  const candidateSpec = specFromFields(specFields);
  const missing = missingSpecFields(candidateSpec, form.provider);
  const advertised = check && !checkStale ? (check.result.models ?? []) : [];
  const suggestions = modelSuggestions(catalog, form.provider, advertised);
  const modelInOptions = suggestions.some(option => option.id === form.model);
  const showCustomModel = customModel || (!!form.model && !modelInOptions);
  const modelSelectValue = form.model && modelInOptions ? form.model : showCustomModel ? "__custom__" : "__none__";
  const deepSpec = form.deep_model ? modelSpecs[form.deep_model] || findCatalogEntry(catalog, form.provider, form.deep_model)?.spec : null;
  const deepMissing = form.deep_model ? missingSpecFields(deepSpec, form.provider) : [];
  const accountModelStatus = checkStale
    ? "La prueba quedó desactualizada; volvé a probar."
    : !check
      ? "Sin comprobar (/models)."
      : !check.result.ok
        ? "No comprobado: la prueba falló."
        : !form.model
          ? "Elegí un modelo para cruzarlo con el listado."
          : check.result.model_found === true
            ? "Sí: aparece en el listado de la cuenta."
            : check.result.model_found === false
              ? "No aparece en el listado; revisá el ID o elegí otro."
              : "El proveedor no devolvió el listado de modelos.";
  return (
    <section className="settings-panel">
      <h2>Proveedor de generación</h2>
      <p>
        Los embeddings son locales. La generación requiere una clave API configurada.
      </p>
      {data && (
        <form className="ai-settings-form" onSubmit={save}>
          <ArcInput label="Nombre del perfil" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <ArcSelect label="Proveedor" value={form.provider} onValueChange={(v) => {
                setForm({...form, provider: v, base_url: defaultBase(v), model: "", deep_model: ""});
                setSpecFields(emptySpecFields(v));
                setCheck(null);
                setCustomModel(false);
                setAdvancedOpen(false);
              }} options={[{value:"openai",label:"OpenAI"},{value:"deepseek",label:"DeepSeek"},{value:"gemini",label:"Gemini"},{value:"claude",label:"Claude / Anthropic"},{value:"compatible",label:"Compatible en origen allowlisted"}]} />
          {form.provider === "compatible" && <ArcInput label="Base URL HTTPS" value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} required />}
          <ArcInput label="API key de escritura única" type="password" autoComplete="new-password" value={key} onChange={(e) => setKey(e.target.value)} placeholder={data.has_key ? "Configurada; deje vacío para conservar" : "Sin configurar"} />
          <p className="muted">Credencial: {data.has_key ? "guardada" : "sin guardar"}{key ? " · hay una clave escrita sin guardar" : ""} · Almacenamiento {data.credential_storage}</p>
          <div className="ai-check">
            <div className="ai-check-head">
              <div>
                <h3>Probar conexión</h3>
                <p>Consulta una sola vez la lista de modelos de la cuenta. No genera contenido, no consume tokens y no valida el gasto.</p>
              </div>
              <ArcButton type="button" variant="secondary" loading={checking} disabled={checking} onClick={() => void runCheck()}>
                {checking ? "Probando…" : "Probar conexión"}
              </ArcButton>
            </div>
            {check && checkView && (
              <div className={`ai-check-result ${checkView.tone}`} role="status">
                <span className={`badge ${checkView.badgeClass}`}>{checkView.badgeText}</span>
                <div className="ai-check-text">
                  <strong>{checkView.title}</strong>
                  <p>{checkView.detail}</p>
                  {checkStale && <p className="ai-check-stale">La configuración cambió después de esta prueba. Vuelva a probar para validar los valores actuales.</p>}
                </div>
              </div>
            )}
          </div>
          <div className="ai-readiness" role="status" aria-label="Estado del perfil">
            <span className="status-pill" data-state={data.has_key || key ? "active" : "inactive"}>{data.has_key || key ? "Clave lista" : "Falta la clave"}</span>
            <span className="status-pill" data-state={check && !checkStale && check.result.ok ? "active" : "inactive"} title={accountModelStatus}>{check && !checkStale && check.result.ok ? "Modelo comprobado en /models" : "Modelo sin comprobar"}</span>
            <span className="status-pill" data-state={!form.model ? "inactive" : missing.length ? "inactive" : "active"}>{!form.model ? "Sin modelo" : missing.length ? "Ficha incompleta" : "Ficha lista"}</span>
          </div>
          <h3>Modelo</h3>
          <ArcSelect label="Modelo" value={modelSelectValue} onValueChange={(v) => {
              if (v === "__none__") return;
              if (v === "__custom__") {
                setCustomModel(true);
                setForm({...form, model: ""});
                setSpecFields(emptySpecFields(form.provider));
              } else chooseModel(v);
            }} options={[{value:"__none__",label:"Elegí un modelo"}, ...suggestions.map(option => ({value: option.id, label: option.label})), {value: "__custom__", label: "Otro modelo (escribir ID)"}]} placeholder="Elegí un modelo" />
          {showCustomModel && <ArcInput label="ID exacto del modelo" value={form.model} onChange={(e) => {
              const id = e.target.value;
              setForm({ ...form, model: id });
              if (modelDrafts[id]) setSpecFields(modelDrafts[id]);
              else if (modelSpecs[id]) setSpecFields(specFieldsFrom(modelSpecs[id], form.provider));
              else {
                const entry = findCatalogEntry(catalog, form.provider, id);
                if (entry?.spec) setSpecFields(specFieldsFrom(entry.spec, form.provider));
              }
            }} maxLength={100} placeholder="Escribí el ID exacto que publica el proveedor" />}
          {catalogEntry && <p className="ai-model-selected"><strong>{catalogEntry.label}</strong> <span className="status-pill" data-state={catalogEntry.status === "verified" ? "active" : "inactive"}>{catalogEntry.status === "verified" ? "ficha verificada" : "pendiente"}</span></p>}
          {form.model && missing.length > 0 && <><ArcAlert tone="warning" title="Falta completar la ficha del modelo">Faltan: {missing.join(" · ")}</ArcAlert><ArcButton type="button" variant="secondary" size="sm" onClick={() => setAdvancedOpen(true)}>Abrir ficha técnica</ArcButton></>}
          <div><ArcSelect label="Modelo profundo (opcional)" value={form.deep_model || "__none__"} onValueChange={(v) => setForm({...form, deep_model: v === "__none__" ? "" : v})} options={[{value:"__none__",label:"Usar el modelo estándar"}, ...(form.deep_model && !suggestions.some(option => option.id === form.deep_model) ? [{value: form.deep_model, label: `${form.deep_model} (actual)`}] : []), ...suggestions.map(option => ({value: option.id, label: option.label}))]} description="Se usa en R2 y cuando pedís análisis profundo. Sin elegir, se reutiliza el estándar." /></div>
          {form.deep_model && deepMissing.length > 0 && <><ArcAlert tone="warning" title="Falta la ficha del modelo profundo">Faltan: {deepMissing.join(" · ")}</ArcAlert><ArcButton type="button" variant="secondary" size="sm" onClick={() => setAdvancedOpen(true)}>Abrir ficha técnica</ArcButton></>}
          <details className="ai-advanced" open={advancedOpen} onToggle={event => setAdvancedOpen(event.currentTarget.open)}>
            <summary>Ficha técnica y opciones avanzadas</summary>
            {form.provider !== "compatible" && <ArcInput label="Base URL HTTPS" value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} required />}
            {form.provider === "claude" && <ArcInput label="ID del workspace de Claude (si la clave no está vinculada a uno)" value={workspaceId} maxLength={100} onChange={e => setWorkspaceId(e.target.value)} description="La ruta compatible OpenAI exige anthropic-workspace-id para claves personales o de servicio con acceso a varios workspaces." />}
            <fieldset className="ai-spec-fields">
              <legend>Ficha del modelo {form.model || "seleccionado"}</legend>
              <p className="muted">Datos técnicos que se congelan en la ruta del trabajo. Tarifas en USD por millón de tokens; el sistema reserva el peor caso. La cota es el cuerpo serializado + 2048 bytes.</p>
              <div className="ai-spec-grid">
                <ArcSelect label="Formato estructurado" value={specFields.format} onValueChange={v => setSpecFields({...specFields, format: v})} options={[{value:"json_schema",label:"json_schema con strict:true"},{value:"json_object",label:"json_object"}]} />
                <ArcInput label="Límite de salida (tokens)" type="number" min="800" max="4096" value={specFields.output_cap} onChange={e => setSpecFields({...specFields, output_cap: e.target.value})} />
                <ArcInput label="Límite de entrada (tokens)" type="number" min="4096" max="100000" value={specFields.input_cap} onChange={e => setSpecFields({...specFields, input_cap: e.target.value})} />
                <ArcInput label="Tiempo máximo (segundos)" type="number" min="1" max="60" value={specFields.timeout_seconds} onChange={e => setSpecFields({...specFields, timeout_seconds: e.target.value})} />
                <ArcInput label="Tarifa de entrada (USD por millón)" type="number" min="0" step="0.0001" value={specFields.input_usd} onChange={e => setSpecFields({...specFields, input_usd: e.target.value})} />
                <ArcInput label="Tarifa de salida (USD por millón)" type="number" min="0" step="0.0001" value={specFields.output_usd} onChange={e => setSpecFields({...specFields, output_usd: e.target.value})} />
                <ArcInput label="Fecha de verificación" type="date" value={specFields.verified_at} onChange={e => setSpecFields({...specFields, verified_at: e.target.value})} />
                <ArcInput label="Fuente oficial (HTTPS)" type="url" value={specFields.source_url} onChange={e => setSpecFields({...specFields, source_url: e.target.value})} />
              </div>
              <ArcCheckbox label="Cota de salida facturable confirmada" description="El parámetro de salida acota toda la salida facturable, incluido razonamiento cuando el proveedor lo cuenta." checked={specFields.billable_output_bounded} onCheckedChange={next => setSpecFields({...specFields, billable_output_bounded: next === true})} />
              <ArcCheckbox label="Gratuidad de la cuenta verificada por el operador" description="Marcar solo si la cuenta es elegible gratis para este uso; no se deduce de una etiqueta «Free» de otro producto." checked={specFields.free_account_verified} onCheckedChange={next => setSpecFields({...specFields, free_account_verified: next === true})} />
              <p className="muted">Método de cota: utf8_bytes_plus_2048_verified · sin gratuidad verificada se exige tarifa de entrada y salida.</p>
            </fieldset>
            {catalogEntry && <div className="ai-model-summary">
              <p><strong>{catalogEntry.label}</strong> · {catalogEntry.notes}</p>
              <p className="muted">Endpoint {catalogEntry.endpoint} · formato {catalogEntry.format} · salida acotada por {catalogEntry.output_parameter} · verificado el {catalog?.as_of}</p>
              {Object.entries(catalogEntry.sources || {}).map(([key, url]) => <p key={key} className="muted"><a href={url} target="_blank" rel="noreferrer">Fuente {key}</a></p>)}
            </div>}
            <div className="switch-row">
              <span>Formato JSON declarado por el perfil</span>
              <ToggleSwitch
                label="Formato JSON declarado por el perfil"
                checked={form.json_mode}
                onChange={(next) => setForm({ ...form, json_mode: next })}
              />
            </div>
            <details><summary>Perfil profundo avanzado opcional</summary>
              <p>JSON avanzado para un segundo proveedor/modelo profundo. No es la ficha del modelo estándar ni acredita créditos de la cuenta.</p>
              <ArcTextarea label="Perfil profundo avanzado opcional" rows={4} value={deepProfileText} onChange={e => setDeepProfileText(e.target.value)} />
            </details>
            <ArcInput label="Clave del perfil profundo opcional" type="password" autoComplete="new-password" value={deepKey} onChange={e=>setDeepKey(e.target.value)} />
            <p className="notice">{data.live_block_reason}</p>
          </details>
          <div className="service-dialog-actions">
            <ArcButton type="button" variant="secondary" onClick={() => void saveDraft()}>Guardar borrador</ArcButton>
            <ArcButton>Guardar y habilitar</ArcButton>
          </div>
        </form>
      )}

      {spendCap && <form onSubmit={saveLimit} aria-label="Límite de gasto de la sesión">
        <h3>Límite de gasto de la sesión</h3>
        <div className="switch-row"><span>Activar límite monetario</span><ToggleSwitch label="Activar límite monetario" checked={limitEnabled} onChange={setLimitEnabled} /></div>
        <div className={limitEnabled ? undefined : "field-disabled"}><ArcInput label="Monto máximo desde la activación (USD)" type="number" min="0.01" max="1000000" step="0.01" required={limitEnabled} disabled={!limitEnabled} value={amountUsd} onChange={e => setAmountUsd(e.target.value)} />{!limitEnabled && <small>Activa el límite para poder fijar el monto.</small>}</div>
        <p>{spendCap.cap_enabled ? `Activo: máximo ${(Number(spendCap.limit_units) / 1e8).toFixed(2)} USD; restante ${Math.max(0, (Number(spendCap.limit_units) - Number(spendCap.spent_units) + Number(spendCap.cap_baseline_spent_units) - Number(spendCap.reserved_units)) / 1e8).toFixed(2)} USD.` : "Desactivado: nuevas solicitudes sin tope monetario de sesión."} El gasto anterior permanece en el historial.</p>
        <ArcButton disabled={savingLimit}>{savingLimit ? "Guardando…" : "Guardar límite"}</ArcButton>
      </form>}

      {cveSettings && <form onSubmit={saveCve} aria-label="Detector de CVE">
        <h3>Detector de CVE</h3>
        <div className="switch-row"><span>Chequeo diario de CVE (NVD)</span><ToggleSwitch label="Chequeo diario de CVE" checked={cveEnabled} onChange={setCveEnabled} /></div>
        <p>Está activado por defecto: el backend —nunca el modelo— consulta una vez al día la base de vulnerabilidades NVD de NIST por la versión confirmada de cada servicio, guardando los CVE que afectan a esa versión junto con la versión corregida cuando NVD la publica. Una versión es confirmada si la declaró el operador o si el propio servicio la publicó vía MCP en su version.json (procedencia «vía MCP»). Los banners detectados en la evidencia son solo sugerencias: nunca se adoptan automáticamente, y sin versión confirmada no se consulta NVD. Es una salida a Internet del backend, autorizada como comportamiento normal del producto. Si lo desactivás, se detiene el chequeo diario; la comprobación manual desde la pestaña CVE o Editar servicio sigue disponible.</p>
        <ArcButton disabled={savingCve}>{savingCve ? "Guardando…" : "Guardar detector"}</ArcButton>
      </form>}


      {message && (
        <p role="status" className="notice">
          {message}
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </section>
  );
}

function Status({ refresh }: { refresh: number }) {
  const [data, setData] = useState<Data>({}),
    [costs, setCosts] = useState<Data>({}),
    [sources, setSources] = useState<Data>({ items: [] });
  useEffect(() => {
    void Promise.all([
      api("/status").then(setData),
      api("/costs").then(setCosts),
      api("/sources").then(setSources),
    ]);
  }, [refresh]);
  const sessionAccount = costs.accounts?.find((a: Data) => a.scope === "session" && a.scope_key === costs.session_id);
  const usd = (units: unknown) => ((Number(units) || 0) / 1e8).toFixed(2);
  return (
    <section className="system-status">
      <h2>Costos</h2>
      <div className="stat-cards">
        <article className="stat-card"><span>Gastado en la sesión</span><strong>USD {usd(sessionAccount?.spent_units)}</strong><small>Sesión {costs.session_id || "—"}</small></article>
        <article className="stat-card"><span>Reservado</span><strong>USD {usd(sessionAccount?.reserved_units)}</strong><small>Solicitudes en curso</small></article>
        <article className="stat-card"><span>Límite de sesión</span><strong>{sessionAccount?.cap_enabled ? "Activo" : "Desactivado"}</strong><small>{sessionAccount?.cap_enabled ? "El tope se aplica a solicitudes nuevas." : "Sin tope monetario; activalo en Ajustes."}</small></article>
        <article className="stat-card"><span>Generación</span><strong>{data.generation_paused ? "Pausada" : data.mode === "live" ? "API" : "Sin API"}</strong><small>{data.model || "Sin modelo"}</small></article>
      </div>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Tabla de costos registrados">
        <ArcTable caption="Costos registrados por ámbito" rows={(costs.accounts || []) as Data[]} rowKey={(a: Data) => a.scope + a.scope_key} emptyMessage="Sin costos registrados" columns={[
          {key: "scope", label: "Ámbito", render: (_v, a) => <>{a.scope === "day" ? "Día UTC" : "Sesión"}<small>{a.scope_key}</small></>},
          {key: "spent_units", label: "Gastado (USD)", render: (_v, a) => usd(a.spent_units)},
          {key: "reserved_units", label: "Reservado (USD)", render: (_v, a) => usd(a.reserved_units)},
        ]} />
      </div>
      <h3>Trabajos de análisis y chat por estado</h3>
      <div className="job-states">
        {costs.jobs?.map((j: Data) => (
          <span key={j.state}>
            <Badge value={j.state} /> {j.count}
          </span>
        ))}
      </div>
      <h2>Estado del sistema</h2>
      <dl>
        <dt>Embeddings locales</dt>
        <dd>
          <Badge value={data.embeddings || "pending"} />
        </dd>
        <dt>Corpus activo</dt>
        <dd>
          <code>{data.knowledge?.active_corpus_id || "No disponible"}</code>
        </dd>
        <dt>Generación</dt>
        <dd>
          {data.generation_paused ? "Pausada por el operador" : data.mode === "live" ? "API" : "Sin API"} · {data.model}
        </dd>
        <dt>Formatos soportados</dt><dd>{data.supported_log_formats?.join(", ")}</dd>
        <dt>Capacidades</dt>
        <dd>Observar, explicar y recomendar comprobaciones humanas.</dd>
      </dl>
      <h2>Fuentes configuradas</h2>
      {sources.next_cursor && <p>Se muestran {sources.items.length} de {sources.total_count} fuentes. Administrá las fuentes de cada servicio en Ajustes.</p>}
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Tabla de fuentes configuradas">
        <ArcTable caption="Fuentes configuradas" rows={(sources.items || []) as Data[]} rowKey="id" emptyMessage="No hay fuentes configuradas" columns={[
          {key: "logical_name", label: "Fuente", render: (_v, s2) => <b>{s2.logical_name}</b>},
          {key: "status", label: "Estado", render: (_v, s2) => <span className="status-pill" data-state={s2.status === "healthy" ? "active" : s2.status === "blocked" ? "deleted" : "inactive"}>{s2.status}</span>},
          {key: "lag_bytes", label: "Bytes pendientes", render: (_v, s2) => number(Number(s2.lag_bytes || 0))},
          {key: "errors", label: "Diagnósticos", render: (_v, s2) => number(Number(s2.errors || 0))},
          {key: "last_error_code", label: "Último error", render: (_v, s2) => s2.last_error_code ? <span className="error">{s2.last_error_code}</span> : "—"},
        ]} />
      </div>
    </section>
  );
}
const root = document.getElementById("root");
if (root)
  createRoot(root).render(
    <React.StrictMode>
      <LangProvider>
        <App />
      </LangProvider>
    </React.StrictMode>,
  );

export function summarizeReview(coverage: Data) {
  const count = (names: string[]) => (coverage.states || []).filter((s: Data) => names.includes(s.state)).reduce((sum: number, s: Data) => sum + Number(s.records), 0);
  return {total:Number(coverage.received || 0), reviewed:count(["live","mock","mixed","inconclusive"]), inconclusive:count(["inconclusive"]), processing:count(["in_progress"]), waiting:count(["pending"]), attention:count(["failed","unknown","unavailable"]), failed:count(["failed"]), blocked:count(["blocked"]), stopped:count(["stopped"]), local:count(["local"])};
}
export function ReviewProgress({data, label}:{data:Data;label:string}) {
  const stats=summarizeReview(data);
  return <div className="review-progress" aria-label={label}>
    <div className="review-progress-head"><div><strong>{number(stats.reviewed)} de {number(stats.total)}</strong><span> registros con resultado</span></div><div className="review-current" role="status" aria-live="polite">{(stats.processing>0||stats.waiting>0)&&<span className="review-spinner" aria-hidden="true"/>}{stats.processing>0?`${number(stats.processing)} en proceso`:stats.waiting>0?"En espera":"Sin procesamiento activo"}</div></div>
    <progress aria-label={`Registros con resultado: ${label}`} value={stats.reviewed} max={Math.max(stats.total,1)} />
    <div className="review-counts"><span><b>{number(stats.processing)}</b> en proceso</span><span><b>{number(stats.waiting)}</b> en espera</span>{stats.failed>0&&<span><b>{number(stats.failed)}</b> fallidos</span>}{stats.blocked>0&&<span><b>{number(stats.blocked)}</b> bloqueados</span>}{stats.attention>stats.failed&&<span><b>{number(stats.attention-stats.failed)}</b> sin resultado</span>}{stats.stopped>0&&<span><b>{number(stats.stopped)}</b> detenidos por el operador</span>}{stats.local>0&&<span><b>{number(stats.local)}</b> locales</span>}</div>
    {stats.waiting>0&&<p className="muted">En cola para revisión. La velocidad depende de la disponibilidad y los límites de la API.</p>}
    {stats.inconclusive>0&&<p className="muted">Entre los resultados, {number(stats.inconclusive)} no son concluyentes.</p>}
  </div>;
}
export function RecordReview({refresh,summaryOnly=false}:{refresh:number;summaryOnly?:boolean}) {
  const [coverage,setCoverage]=useState<Data|null>(null),[records,setRecords]=useState<Data[]>([]),[error,setError]=useState(""),[state,setState]=useState(""),[service,setService]=useState(""),[run,setRun]=useState(""),[more,setMore]=useState<string|null>(null);
  const [record,setRecord]=useState<Data|null>(null);
  const [page,setPage]=useState(0),[cursors,setCursors]=useState<(string | undefined)[]>([undefined]);
  const [batchCoverage,setBatchCoverage]=useState<Data|null>(null),[batchError,setBatchError]=useState(""),[batchReload,setBatchReload]=useState(0);
  const [batches,setBatches]=useState<Data[]>([]),[selectedBatch,setSelectedBatch]=useState(""),[feedback,setFeedback]=useState(""),[starting,setStarting]=useState(false),[stopping,setStopping]=useState(false),[confirmStop,setConfirmStop]=useState(false),[reviewOpen,setReviewOpen]=useState(false);
  useEffect(()=>{api("/review-batches").then(d=>{setBatches(d.items);setSelectedBatch((v:string)=>v||d.items[0]?.id||"");}).catch(e=>setFeedback(e.message));},[]);
  useEffect(()=>{let current=true,seq=0;setBatchCoverage(null);setBatchError("");
    const update=()=>{if(!selectedBatch)return;const requestId=++seq;api("/coverage?run_id="+encodeURIComponent(selectedBatch)).then(v=>{if(current&&requestId===seq){setBatchCoverage(v);setBatchError("");}}).catch(()=>{if(current&&requestId===seq){setBatchCoverage(null);setBatchError("No se pudo actualizar el avance del lote.");}});};
    update();const timer=setInterval(update,5000);return()=>{current=false;clearInterval(timer);};},[selectedBatch,batchReload]);
  async function startReview(failedOnly=false){setStarting(true);try{const result=await api("/reviews","POST",{run_id:selectedBatch,failed_only:failedOnly});const message=`${failedOnly?"Reintento de fallidos iniciado":"Revisión iniciada"}: ${result.segments} segmentos programados.`;setFeedback(message);notifyToast("success",failedOnly?"Reintento de fallidos iniciado":"Revisión iniciada",message);setBatchReload(n=>n+1);await load();}catch(e){setFeedback((e as Error).message);notifyToast("error",failedOnly?"No se pudo reintentar los fallidos":"No se pudo iniciar la revisión",(e as Error).message);}finally{setStarting(false);}}
  async function stopReview(){if(!selectedBatch)return;setStopping(true);try{const result=await api("/reviews/stop","POST",{run_id:selectedBatch});const message=`Revisión detenida: ${result.stopped} trabajo(s) pendiente(s) no se enviarán${Number(result.still_running)>0?`; ${result.still_running} ya en vuelo terminará(n) y se contabilizará(n) una sola vez`:""}.`;setFeedback(message);notifyToast(Number(result.still_running)>0?"warning":"success","Revisión detenida",message);setConfirmStop(false);setBatchReload(n=>n+1);await load();}catch(e){setFeedback((e as Error).message);notifyToast("error","No se pudo detener la revisión",(e as Error).message);}finally{setStopping(false);}}
  const request=useRef(0);
  const load=useCallback(async(cursor?:string)=>{const seq=++request.current;try {
    const filters=new URLSearchParams();if(service)filters.set("service_id",service);if(run)filters.set("run_id",run);
    const c=await api("/coverage?"+filters);if(seq!==request.current)return;setCoverage(c);
    if(!summaryOnly){if(state)filters.set("state",state);if(cursor)filters.set("cursor",cursor);const r=await api("/records?"+filters);if(seq!==request.current)return;setRecords(r.items);setMore(r.next_cursor);}
    setError("");
  }catch(e){if(seq===request.current)setError((e as Error).message);}},[service,run,state,summaryOnly]);
  useEffect(()=>{setPage(0);setCursors([undefined]);},[state,service,run]);
  useEffect(()=>{void load(cursors[page]);const timer=setInterval(()=>void load(cursors[page]),5000);return()=>clearInterval(timer);},[load,refresh,page,cursors]);
  if(summaryOnly) {
    const summaryReasons: Data[] = coverage?.job_reasons || [];
    const summaryErrors: Data[] = coverage?.attempt_errors || [];
    const countReason = (reason: string) => summaryReasons.filter((item: Data) => item.reason === reason).reduce((n: number, item: Data) => n + Number(item.count || 0), 0);
    const failing = summaryErrors.reduce((n: number, item: Data) => n + Number(item.count || 0), 0);
    const circuit = countReason("circuit_open");
    const resultRecords = (data: Data | null) => (data?.states || []).filter((item: Data) => ["live", "mock", "mixed"].includes(item.state)).reduce((n: number, item: Data) => n + Number(item.records || 0), 0);
    const globalResults = resultRecords(coverage);
    const detail = (data: Data | null) => {
      const reasons: Data[] = data?.job_reasons || [];
      const errors: Data[] = data?.attempt_errors || [];
      const value = (list: Data[], key: string, match: string) => list.filter((item: Data) => item[key] === match).reduce((n: number, item: Data) => n + Number(item.count || 0), 0);
      return {circuit: value(reasons, "reason", "circuit_open"), invalid: value(reasons, "reason", "invalid_provider_response"), blocked: value(reasons, "reason", "capability_tariff_or_bound_unverified"), stopped: value(reasons, "reason", "operator_stopped"), errors};
    };
    const selected = detail(batchCoverage);
    const selectedStats = batchCoverage ? summarizeReview(batchCoverage) : null;
    return <section className="dashboard-panel review-summary" aria-label="Revisión de registros">
      <div className="panel-heading"><div><h2>Revisión de registros</h2><p className="muted">Seguimiento de los logs cargados</p></div><ArcButton type="button" onClick={()=>setReviewOpen(true)}>Abrir revisión</ArcButton></div>
      {coverage ? <ReviewProgress data={coverage} label="Todos los registros"/> : <p role={error?"alert":"status"}>{error || "Cargando avance de los registros…"}</p>}
      {(failing > 0 || circuit > 0) && <p className="muted">{globalResults > 0 ? `La API ya completó ${number(globalResults)} registro(s); algunas respuestas anteriores se rechazaron.` : "La API responde, pero aún no hay resultados válidos."} {circuit > 0 ? "El gateway espera 60 s antes del próximo envío." : ""} Abrí la revisión para ver el detalle.</p>}
      <ArcDialog open={reviewOpen} onOpenChange={setReviewOpen}>
        <ArcDialogContent title="Revisión de registros" className="service-dialog review-dialog">
          <h3>Estado general</h3>
          {coverage ? <ReviewProgress data={coverage} label="Todos los registros"/> : <p role={error?"alert":"status"}>{error || "Cargando avance de los registros…"}</p>}
          {(coverage?.states||[]).some((s:Data)=>s.state==="blocked")&&<ArcAlert tone="info" title="El historial incluye registros bloqueados">Son trabajos anteriores con la ruta congelada; no impiden que una revisión nueva use la ficha actual. Revisá Ajustes si el lote seleccionado también queda bloqueado.</ArcAlert>}
          <h3>Lote seleccionado</h3>
          <div className="review-actions"><ArcSelect label="Lote a revisar" value={selectedBatch} onValueChange={setSelectedBatch} options={batches.map(b=>({value: b.id, label: `${time(b.received_at)} · ${number(b.records)} registros`}))} /><ArcButton disabled={!selectedBatch||starting} onClick={()=>void startReview()}>{starting?<><span className="review-spinner" aria-hidden="true"/> Preparando…</>:"Iniciar nueva revisión"}</ArcButton><ArcButton type="button" variant="secondary" disabled={!selectedBatch||stopping||starting} onClick={()=>setConfirmStop(true)}>{stopping?"Deteniendo…":"Detener revisión"}</ArcButton></div>
          {confirmStop && <><ArcAlert tone="warning" title="¿Detener la revisión de este lote?" onDismiss={()=>setConfirmStop(false)}>Los trabajos que todavía no se enviaron no se enviarán. Los que ya están en vuelo terminan y se contabilizan una sola vez.</ArcAlert><div className="service-dialog-actions"><ArcButton type="button" variant="secondary" onClick={()=>setConfirmStop(false)}>Cancelar</ArcButton><ArcButton type="button" loading={stopping} onClick={()=>void stopReview()}>Confirmar detención</ArcButton></div></>}
          {selectedBatch && (batchCoverage ? <div className="review-batch"><ReviewProgress data={batchCoverage} label="Lote seleccionado"/>
            {selected.circuit > 0 && <ArcAlert tone="warning" title="La API está en pausa temporal">El gateway encadenó tres respuestas fallidas o ambiguas y espera 60 segundos antes del próximo envío. No es una caída de red ni un problema de clave.</ArcAlert>}
            {(selected.invalid > 0 || selected.errors.length > 0) && <ArcAlert tone={resultRecords(batchCoverage) > 0 ? "info" : "warning"} title={resultRecords(batchCoverage) > 0 ? "La API funciona; algunas respuestas se rechazaron" : "La API responde, pero la respuesta no cumple el contrato"}>{resultRecords(batchCoverage) > 0 ? `Ya hay ${resultRecords(batchCoverage)} registro(s) completados. ` : ""}{selected.invalid > 0 ? `${selected.invalid} trabajo(s) fallaron la validación.` : ""} {selected.errors.length > 0 ? `Códigos: ${selected.errors.map((e: Data) => `${e.error} (${e.count})`).join(", ")}.` : ""} Las respuestas inválidas no se reenvían automáticamente.</ArcAlert>}
            {selected.blocked > 0 && <ArcAlert tone="warning" title="Hay trabajos bloqueados por ficha o tarifa">Completá la ficha del modelo en Ajustes → Proveedor de generación. No se envió nada con una ficha incompleta.</ArcAlert>}
            {selected.stopped > 0 && <ArcAlert tone="info" title="Hay trabajos detenidos por el operador">No se reenviarán automáticamente. Una revisión manual nueva puede retomarlos.</ArcAlert>}
            {selectedStats && selectedStats.failed > 0 && <div className="review-retry"><p className="muted">No hay procesamiento activo. Los fallidos se reintentan automáticamente hasta 3 veces. Si vuelven a fallar, quedan para reintento manual y el worker pasa al siguiente registro; reintentar solo esos registros no vuelve a analizar los completados.</p><ArcButton type="button" variant="secondary" disabled={starting} onClick={()=>void startReview(true)}>{starting ? "Reintentando…" : `Reintentar ${number(selectedStats.failed)} fallidos`}</ArcButton></div>}
          </div> : <p role={batchError?"alert":"status"}>{batchError || "Cargando avance del lote…"}</p>)}
          <p className="muted">La revisión analiza registros elegibles independientemente de las reglas; el contenido hostil o sensible permanece local. Los envíos ambiguos no se repiten.</p>
          {batchCoverage?.costs.pending_upper_units!=null&&<p className="muted">Cota de los trabajos actualmente pendientes del lote: USD {(batchCoverage.costs.pending_upper_units/1e8).toFixed(8)}. La cota de una revisión nueva puede ser distinta.</p>}
          {feedback&&<p role="status">{feedback}</p>}
        </ArcDialogContent>
      </ArcDialog>
    </section>;
  }
  return <section className="coverage-panel" aria-label="Cobertura de registros">
    <h2>Cobertura de registros</h2>
    <p>Recibidos {number(coverage?.received||0)}. Cada registro ocupa un solo estado; los segmentos no son logs adicionales.</p>
    {!summaryOnly&&<div className="review-filters"><ArcSelect label="Estado de revisión" value={state || "__all__"} onValueChange={v=>setState(v === "__all__" ? "" : v)} options={[{value:"__all__",label:"Todos"}, ...["pending","in_progress","mock","live","mixed","local","inconclusive","blocked","failed","unknown","unavailable"].map(s=>({value: s, label: states[s]||s}))]} /><ServicePicker api={api} label="Servicio de revisión" value={service} onChange={setService} refresh={refresh} /><ArcInput label="Lote de revisión" value={run} onChange={e=>setRun(e.target.value)} placeholder="Todos los lotes" /></div>}
    {error&&<p role="alert">{error}</p>}
    <div className="table-scroll"><ArcTable caption="Conciliación de revisión primaria" rows={(coverage?.states || []) as Data[]} rowKey="state" emptyMessage="Sin estados" columns={[
      {key: "state", label: "Estado", render: (_v, st) => <Badge value={st.state} />},
      {key: "records", label: "Registros", render: (_v, st) => number(st.records)},
      {key: "segments", label: "Segmentos completos / totales", render: (_v, st) => `${number(st.completed_segments)} / ${number(st.segments)}`},
      {key: "without_parser", label: "Sin parser", render: (_v, st) => number(st.without_parser)},
    ]} /></div>
    <p className="muted">La revisión con API se muestra por separado de los registros locales por política. Sin indicios observados no garantiza ausencia de amenazas.</p>
    <p>Bloques: {coverage?.costs.blocks||0} · Intentos: {coverage?.costs.attempts||0} · Costo primario USD {((coverage?.costs.spent_units||0)/1e8).toFixed(8)} · Duplicados evitados: {coverage?.duplicates_avoided||0}</p>
    <details><summary>Alcance y costo pendiente</summary><p>La cobertura cuenta disposiciones validadas; no garantiza detectar todas las amenazas.</p><p>{coverage?.pending_cost_estimate}</p>{coverage?.costs.pending_upper_units!=null&&<p>Cota pendiente USD {(coverage.costs.pending_upper_units/1e8).toFixed(8)}</p>}</details>
    {!summaryOnly&&<><h3>Registros preservados</h3><div className="table-scroll"><ArcTable caption="Registros preservados" rows={records as Data[]} rowKey="id" emptyMessage="Sin registros" columns={[
      {key: "received_at", label: "Recepción", render: (_v, r) => time(r.received_at)},
      {key: "service", label: "Servicio", render: (_v, r) => <>{r.service}<br /><small>{r.parser === "unparsed" ? "Sin parser" : r.parser}</small></>},
      {key: "coverage_state", label: "Estado", render: (_v, r) => <><Badge value={r.coverage_state} />{r.jobs?.map((j: Data) => <small key={j.id}> {states[j.state] || j.state}: {reviewReason(j.reason)}</small>)}</>},
      {key: "safe_text", label: "Contenido", render: (_v, r) => <span className="record-preview">{r.content_expired_at ? "Contenido temporal expirado" : r.local_reason ? reviewReason(r.local_reason) : r.safe_text}</span>},
      {key: "segments", label: "Segmentos", render: (_v, r) => `${r.completed_segments}/${r.segments}`},
      {key: "detail", label: "Detalle", render: (_v, r) => <ArcButton onClick={() => void api("/records/" + r.id).then(setRecord).catch(e => setError(e.message))}>Ver contenido</ArcButton>},
    ]} /></div><nav className="pagination" aria-label="Páginas de registros"><ArcButton disabled={page===0} onClick={()=>setPage(p=>p-1)}>Anterior</ArcButton><span>Página {page+1}</span><ArcButton disabled={!more} onClick={()=>{if(more){setCursors(c=>[...c.slice(0,page+1),more]);setPage(p=>p+1);}}}>Siguiente</ArcButton></nav>{record&&<section className="event" aria-label="Contenido del registro"><h3>Contenido redactado y segmentos</h3><ArcButton onClick={()=>setRecord(null)}>Cerrar contenido</ArcButton><p>Hash original <code>{record.content_hash}</code></p><p>Parser: {record.parser} · {record.diagnostic}</p><pre>{record.content_expired_at ? "Contenido temporal expirado; se conservan los hashes y el estado de revisión." : record.safe_text}</pre>{record.segments?.map((s:Data)=><details key={s.id}><summary>Segmento {s.ordinal+1}: bytes {s.byte_start}–{s.byte_end} · {s.disposition||"pendiente"} · {s.origin||"sin respuesta"}</summary><pre>{s.content}</pre><code>{s.content_hash}</code></details>)}</section>}</>}
  </section>
}
function BusinessRules(){
 const [data,setData]=useState<Data|null>(null),[id,setId]=useState("R1"),[service,setService]=useState(""),[enabled,setEnabled]=useState(true),[threshold,setThreshold]=useState(5),[windowSeconds,setWindow]=useState(60),[notice,setNotice]=useState(""),[page,setPage]=useState(0),[serviceNames,setServiceNames]=useState<Record<string,string>>({});
 const PAGE_SIZE=10;
 useEffect(()=>{api("/business-rules").then(setData).catch(e=>setNotice(e.message));},[]);
 useEffect(()=>{void api("/services?state=all&limit=100").then((d:Data)=>{const map:Record<string,string>={};(d.items||[]).forEach((item:Data)=>{map[item.id]=item.name;});setServiceNames(map);}).catch(()=>{});},[]);
 const rules: Data[] = data?.definition.rules || [];
 const pageCount = Math.max(1, Math.ceil(rules.length / PAGE_SIZE));
 const pageRules = rules.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
 async function persist(nextRules: Data[], message: string){try{await api("/business-rules","PUT",{expected_version:data?.version,definition:{rules:nextRules}});setData(await api("/business-rules"));setNotice(message);notifyToast("success","Reglas actualizadas",message);}catch(e){setNotice((e as Error).message);notifyToast("error","No se pudieron guardar las reglas",(e as Error).message);}}
 async function save(e:React.FormEvent){e.preventDefault();const rule={id,service_id:service||null,enabled,threshold,window_seconds:windowSeconds};const rest=rules.filter((r:Data)=>r.id!==id||r.service_id!==rule.service_id);await persist([...rest,rule],"Regla guardada. No altera la cobertura IA ni cambia la configuración de la API.");}
 function edit(r:Data){setId(r.id);setService(r.service_id||"");setEnabled(r.enabled!==false);setThreshold(Number(r.threshold));setWindow(Number(r.window_seconds));setNotice(`Editando la regla ${r.id} (${r.service_id ? serviceNames[r.service_id] || r.service_id : "todos los servicios"}): ajustá los valores y tocá Guardar regla.`);}
 async function remove(r:Data){await persist(rules.filter((x:Data)=>!(x.id===r.id&&x.service_id===r.service_id)),`Regla ${r.id} retirada de la configuración activa.`);}
 return <section className="coverage-panel"><h2>Reglas empresariales locales</h2><p>R1: fallos; R2: éxito tras fallos; R3: errores. R4 permanece inmutable. Configuración de esta instalación, sin aislamiento multiempresa. Los registros siguen en revisión aunque se deshabilite una regla.</p>
 <p className="muted">Configuración activa v{data?.version ?? "—"} · {rules.length} {rules.length === 1 ? "regla" : "reglas"} (una por combinación de regla y servicio).</p>
 <div className="table-wrap" tabIndex={0} role="region" aria-label="Tabla de reglas empresariales">
   <ArcTable caption="Reglas empresariales activas" rows={pageRules} rowKey={(r: Data) => r.id + ":" + (r.service_id || "")} emptyMessage="Todavía no hay reglas empresariales: agregá la primera con el formulario de abajo." columns={[
     {key: "id", label: "Regla", render: (_v, r) => <strong>{r.id}</strong>},
     {key: "service_id", label: "Servicio", render: (_v, r) => r.service_id ? (serviceNames[r.service_id] || r.service_id) : "Todos los servicios"},
     {key: "enabled", label: "Estado", render: (_v, r) => <span className="status-pill" data-state={r.enabled !== false ? "active" : "inactive"}>{r.enabled !== false ? "Habilitada" : "Deshabilitada"}</span>},
     {key: "threshold", label: "Umbral", render: (_v, r) => number(Number(r.threshold))},
     {key: "window_seconds", label: "Ventana (s)", render: (_v, r) => number(Number(r.window_seconds))},
     {key: "actions", label: "Acciones", render: (_v, r) => <div className="service-row-actions"><ArcButton type="button" variant="secondary" onClick={() => edit(r)}>Editar</ArcButton><ArcButton type="button" variant="ghost" onClick={() => void remove(r)}>Quitar</ArcButton></div>},
   ]} />
 </div>
 {rules.length > PAGE_SIZE && <nav className="pagination" aria-label="Páginas de reglas empresariales"><span>Página {page + 1} de {pageCount} · {rules.length} reglas</span><ArcButton type="button" variant="secondary" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Anterior</ArcButton><ArcButton type="button" variant="secondary" disabled={page >= pageCount - 1} onClick={() => setPage(p => p + 1)}>Siguiente</ArcButton></nav>}
 <h3>Agregar o editar una regla</h3>
 <form onSubmit={save}><ArcSelect label="Regla" value={id} onValueChange={setId} options={["R1","R2","R3"].map(r=>({value: r, label: r}))} /><ServicePicker api={api} label="Servicio de regla" value={service} onChange={setService} /><div className="switch-row"><span>Habilitada</span><ToggleSwitch label="Habilitada" checked={enabled} onChange={setEnabled} /></div><div className="range-row"><ArcSlider label="Umbral de la regla" min={1} max={100} step={1} value={threshold} onValueChange={v=>setThreshold(v as number)} /><ArcInput label="Umbral exacto" type="number" min={1} max={100} value={threshold} onChange={e=>setThreshold(Number(e.target.value))} /></div><div className="range-row"><ArcSlider label="Ventana de la regla en segundos" min={1} max={600} step={1} value={windowSeconds} onValueChange={v=>setWindow(v as number)} /><ArcInput label="Ventana exacta en segundos" type="number" min={1} max={600} value={windowSeconds} onChange={e=>setWindow(Number(e.target.value))} /></div><ArcButton disabled={!data}>Guardar regla</ArcButton></form><p role="status">{notice}</p></section>
}
