import {useCallback, useEffect, useState} from "react";
import { Button as ArcButton } from "@/components/arc/button/button";
import { Select as ArcSelect } from "@/components/arc/select/select";
import { Input as ArcInput } from "@/components/arc/input/input";
import { Textarea as ArcTextarea } from "@/components/arc/textarea/textarea";
import { Checkbox as ArcCheckbox } from "@/components/arc/checkbox/checkbox";
import { Tabs as ArcTabs, TabsList as ArcTabsList, TabsTrigger as ArcTabsTrigger } from "@/components/arc/tabs/tabs";
import { SortableDataTable as ArcTable } from "@/components/arc/sortable-data-table/sortable-data-table";
import type {ServiceData} from "./services";
import { notifyToast } from "./toast";

type Api = (path: string, method?: string, body?: unknown) => Promise<ServiceData>;

export const CLASSIFICATION_LABELS: Record<string, string> = {
  within_declared_boundary: "Dentro de superficie declarada",
  outside_declared_boundary: "Fuera de superficie declarada",
  method_not_allowed: "Método no permitido en la ruta",
  encoded_traversal_attempt: "Posible traversal codificado",
  ambiguous_normalization: "Normalización ambigua",
  unexpected_structure_change: "Cambio de estructura no esperado",
  sensitive_structure_change: "Cambio en zona sensible",
  authentication_anomaly: "Anomalía de autenticación",
  application_error_anomaly: "Anomalía de errores de aplicación",
  boundary_unknown: "Sin superficie declarada",
  insufficient_evidence: "Evidencia insuficiente",
};

export function ClassificationBadge({value}: {value?: string | null}) {
  if (!value || !CLASSIFICATION_LABELS[value]) return null;
  return <span className="classification-badge" data-classification={value}>{CLASSIFICATION_LABELS[value]}</span>;
}

const TABS = [
  {id: "http", label: "HTTP"},
  {id: "filesystem", label: "Estructura"},
  {id: "authentication", label: "Autenticación"},
  {id: "application", label: "Aplicación"},
  {id: "source", label: "Fuentes y limitaciones"},
] as const;

const CAPABILITY_NOTES: Record<string, string> = {
  http: "Rutas que el servicio expone de verdad. Una solicitud fuera de esta superficie es una señal sospechosa: no prueba acceso ni compromiso. Declarar una ruta no prueba que sea segura ni habilita ninguna acción.",
  filesystem: "Zonas del mapa de estructura (solo metadatos) cuyo cambio importa. El sistema nunca abre archivos: una ruta nueva es un indicio para verificación humana, no una webshell confirmada.",
  authentication: "Comportamiento esperado de la autenticación. Las plantillas R1 (ráfaga de fallos) y R2 (éxito tras fallos) se configuran por fuente en su panel «Reglas»; acá se declara lo esperado y sus límites.",
  application: "Comportamiento esperado de la aplicación. La plantilla R3 (ráfaga de errores) se configura por fuente en su panel «Reglas»; acá se declara lo esperado y sus límites.",
  source: "Qué puede entregar cada fuente de verdad. Si una fuente no aporta rutas, usuarios o estados HTTP, Sentinel no lo inventa: la clasificación lo declara como evidencia insuficiente.",
};

const errText = (e: unknown) => (e as Error)?.message || "Error inesperado";

export function ObservabilityPanel({api, service, sources}: {api: Api; service: ServiceData; sources: ServiceData[]}) {
  const [tab, setTab] = useState<string>("http");
  const [items, setItems] = useState<ServiceData[]>([]);
  const [total, setTotal] = useState(0);
  const [fingerprint, setFingerprint] = useState("");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [exposure, setExposure] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<ServiceData | null>(null);
  const [creating, setCreating] = useState(false);
  const [history, setHistory] = useState<ServiceData[] | null>(null);
  const [form, setForm] = useState<ServiceData>({});

  const load = useCallback(async () => {
    const params = new URLSearchParams({scope: tab, limit: String(pageSize), offset: String(page * pageSize)});
    if (status) params.set("status", status);
    if (exposure && tab === "http") params.set("exposure", exposure);
    if (query.trim()) params.set("q", query.trim());
    const data = await api(`/services/${service.id}/observability?${params}`);
    setItems(data.items || []);
    setTotal(data.total || 0);
    setFingerprint(data.fingerprint || "");
  }, [api, service.id, tab, page, pageSize, status, exposure, query]);

  useEffect(() => { void load().catch(e => setError(errText(e))); }, [load]);
  useEffect(() => { setPage(0); setCreating(false); setEditing(null); }, [tab]);

  function openCreate() {
    setCreating(true);
    setEditing(null);
    setForm(tab === "http"
      ? {path_pattern: "", match_kind: "prefix", exposure: "public", methods: "GET", expected_behavior: ""}
      : tab === "filesystem"
        ? {root_alias: "demo-logs", directory: "", sensitivity: "expected", expected_change: false}
        : {expected_behavior: ""});
  }

  function openEdit(item: ServiceData) {
    setEditing(item);
    setCreating(false);
    const c = item.config || {};
    setForm(tab === "http"
      ? {path_pattern: c.path_pattern || "", match_kind: c.match_kind || "exact", exposure: c.exposure || "public", methods: (c.allowed_methods || []).join(", "), expected_behavior: c.expected_behavior || ""}
      : tab === "filesystem"
        ? {root_alias: c.root_alias || "demo-logs", directory: c.directory || "", sensitivity: c.sensitivity || "expected", expected_change: !!c.expected_change}
        : {expected_behavior: c.expected_behavior || ""});
  }

  async function save(description: string) {
    setBusy(true); setError("");
    try {
      const config = tab === "http"
        ? {path_pattern: String(form.path_pattern || "").trim(), match_kind: form.match_kind, exposure: form.exposure, allowed_methods: String(form.methods || "").split(",").map((m: string) => m.trim().toUpperCase()).filter(Boolean), expected_behavior: String(form.expected_behavior || "")}
        : tab === "filesystem"
          ? {root_alias: form.root_alias, directory: String(form.directory || "").trim(), sensitivity: form.sensitivity, expected_change: !!form.expected_change}
          : {expected_behavior: String(form.expected_behavior || "")};
      const entryKind = tab === "http" ? "route" : tab === "filesystem" ? "zone" : "note";
      if (editing) await api(`/services/${service.id}/observability/${editing.entry_id}`, "PUT", {config, description});
      else await api(`/services/${service.id}/observability`, "POST", {scope: tab, entry_kind: entryKind, config, description});
      setCreating(false); setEditing(null);
      await load();
      notifyToast("success","Límite observable guardado","La revisión nueva queda registrada en el historial del servicio.");
    } catch (e) { setError(errText(e)); notifyToast("error","No se pudo guardar el límite observable",errText(e)); } finally { setBusy(false); }
  }

  async function setEntryStatus(item: ServiceData, next: string) {
    setBusy(true); setError("");
    try { await api(`/services/${service.id}/observability/${item.entry_id}`, "PUT", {status: next}); await load(); notifyToast("success", next === "retired" ? "Límite retirado" : "Límite reactivado", "La evidencia histórica conserva su clasificación."); }
    catch (e) { setError(errText(e)); notifyToast("error","No se pudo cambiar el estado del límite",errText(e)); } finally { setBusy(false); }
  }

  async function showHistory(item: ServiceData) {
    try { const data = await api(`/services/${service.id}/observability/${item.entry_id}/history`); setHistory(data.items || []); }
    catch (e) { setError(errText(e)); notifyToast("error","No se pudo cargar el historial del límite",errText(e)); }
  }

  async function revert(revision: number) {
    if (!history?.length) return;
    setBusy(true); setError("");
    try {
      await api(`/services/${service.id}/observability/${history[0].entry_id}/revert`, "POST", {revision});
      setHistory(null);
      await load();
      notifyToast("success","Revisión restaurada","Se creó una revisión nueva; el historial anterior permanece.");
    } catch (e) { setError(errText(e)); notifyToast("error","No se pudo restaurar la revisión",errText(e)); } finally { setBusy(false); }
  }

  async function seedLab() {
    setBusy(true); setError("");
    try { await api(`/services/${service.id}/observability-seed-lab`, "POST", {}); await load(); notifyToast("success","Conjunto inicial cargado","Las rutas del laboratorio quedan editables en la pestaña HTTP."); }
    catch (e) { setError(errText(e)); notifyToast("error","No se pudo cargar el conjunto inicial",errText(e)); } finally { setBusy(false); }
  }

  const pages = Math.max(1, Math.ceil(total / pageSize));
  const [description, setDescription] = useState("");
  useEffect(() => { setDescription(editing?.description || ""); }, [editing, creating]);

  return <section className="service-sources observability-panel" aria-labelledby="observability-heading">
    <div className="list-heading"><h3 id="observability-heading">Límites observables del servicio</h3></div>
    <p className="muted">Lo que este servicio debería hacer, declarado por vos: rutas HTTP, zonas de estructura y comportamiento esperado. Sentinel compara la evidencia contra estos límites y clasifica sin inventar certeza: un intento observado no es un acceso confirmado. Huella del perfil activo: <code>{fingerprint ? fingerprint.slice(0, 12) : "sin entradas"}</code></p>
    <ArcTabs value={tab} onValueChange={v => setTab(v as typeof tab)}>
      <ArcTabsList className="obs-tabs" aria-label="Ámbitos de límites observables">
        {TABS.map(t => <ArcTabsTrigger key={t.id} value={t.id}>{t.label}</ArcTabsTrigger>)}
      </ArcTabsList>
    </ArcTabs>
    <p className="muted">{CAPABILITY_NOTES[tab]}</p>
    {error && <p role="alert">{error}</p>}
    {tab === "source" ? <>
      <div className="table-scroll"><ArcTable caption="Fuentes y limitaciones" rows={sources} rowKey="id" emptyMessage="Sin fuentes" columns={[
        {key: "kind", label: "Fuente", render: (_v, src) => src.kind === "mcp" ? "MCP de lectura" : "Carpeta de logs"},
        {key: "system", label: "Sistema / protocolo", render: (_v, src) => `${src.analysis?.system || "—"} / ${src.analysis?.protocol || "—"}`},
        {key: "aporte", label: "Qué aporta", render: (_v, src) => src.kind === "mcp" ? "Registros del recurso configurado" : "Archivos que coinciden con el selector"},
        {key: "limitaciones", label: "Limitaciones", render: (_v, src) => src.analysis?.system === "nginx" ? "El JSON de laboratorio trae la ruta ya normalizada por Nginx: el target original no consta y no se reconstruye." : "Solo aporta los campos de su formato; lo que no venga en el registro queda como evidencia insuficiente."},
      ]} /></div>
      {!sources.length && <p>Este servicio todavía no tiene fuentes: sin fuentes no hay evidencia que clasificar.</p>}
      <div className="service-row-actions">
        <ArcButton type="button" disabled={busy} onClick={() => void seedLab()}>Cargar conjunto inicial del laboratorio Nginx</ArcButton>
        <span className="muted">Crea «/» pública, «/secure/» autenticada y «/files/» pública controlada en la pestaña HTTP. Es editable y solo se aplica si el servicio aún no tiene rutas.</span>
      </div>
    </> : <>
      <div className="cve-toolbar">
        <ArcInput label="Buscar" value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} placeholder="Ruta o descripción" />
        <ArcSelect label="Estado" value={status || "__all__"} onValueChange={v => { setStatus(v === "__all__" ? "" : v); setPage(0); }} options={[{value:"__all__",label:"Todos"},{value:"active",label:"Activas"},{value:"retired",label:"Retiradas"}]} />
        {tab === "http" && <ArcSelect label="Exposición" value={exposure || "__all__"} onValueChange={v => { setExposure(v === "__all__" ? "" : v); setPage(0); }} options={[{value:"__all__",label:"Todas"},{value:"public",label:"Pública"},{value:"authenticated",label:"Autenticada"},{value:"internal",label:"Interna"},{value:"sensitive",label:"Sensible"}]} />}
        <ArcSelect label="Por página" value={String(pageSize)} onValueChange={v => { setPageSize(Number(v)); setPage(0); }} options={[{value:"10",label:"10"},{value:"25",label:"25"},{value:"50",label:"50"}]} />
        {!service.deleted_at && <ArcButton type="button" onClick={openCreate}>Nueva entrada</ArcButton>}
      </div>
      <div className="table-scroll"><ArcTable caption="Entradas de límites observables" rows={items} rowKey="entry_id" emptyMessage="Sin entradas" columns={[
        ...(tab === "http" ? [
          {key: "path_pattern", label: "Ruta / patrón", render: (_v: unknown, item: ServiceData) => <code>{item.config?.path_pattern}</code>},
          {key: "match_kind", label: "Coincidencia", render: (_v: unknown, item: ServiceData) => ({exact: "Exacta", prefix: "Prefijo", template: "Plantilla"} as Record<string, string>)[item.config?.match_kind as string] || item.config?.match_kind},
          {key: "exposure", label: "Exposición", render: (_v: unknown, item: ServiceData) => ({public: "Pública", authenticated: "Autenticada", internal: "Interna", sensitive: "Sensible"} as Record<string, string>)[item.config?.exposure as string] || item.config?.exposure},
          {key: "methods", label: "Métodos", render: (_v: unknown, item: ServiceData) => (item.config?.allowed_methods || []).join(", ")},
        ] : tab === "filesystem" ? [
          {key: "root_alias", label: "Raíz / directorio", render: (_v: unknown, item: ServiceData) => <code>{item.config?.root_alias}{item.config?.directory ? `/${item.config.directory}` : ""}</code>},
          {key: "sensitivity", label: "Sensibilidad", render: (_v: unknown, item: ServiceData) => item.config?.sensitivity === "sensitive" ? "Sensible" : "Esperada"},
          {key: "expected_change", label: "Cambio esperado", render: (_v: unknown, item: ServiceData) => item.config?.expected_change ? "Sí" : "No"},
        ] : [
          {key: "expected_behavior", label: "Comportamiento esperado", render: (_v: unknown, item: ServiceData) => item.config?.expected_behavior},
        ]),
        {key: "description", label: "Descripción", render: (_v: unknown, item: ServiceData) => item.description || "—"},
        {key: "status", label: "Estado", render: (_v: unknown, item: ServiceData) => item.status === "active" ? "Activa" : "Retirada"},
        {key: "revision", label: "Revisión", render: (_v: unknown, item: ServiceData) => `v${item.revision}`},
        {key: "actions", label: "Acciones", render: (_v: unknown, item: ServiceData) => <div className="service-row-actions">
            <ArcButton type="button" variant="secondary" onClick={() => openEdit(item)}>Editar</ArcButton>
            <ArcButton type="button" variant="secondary" onClick={() => void showHistory(item)}>Historial</ArcButton>
            <ArcButton type="button" variant="secondary" disabled={busy} onClick={() => void setEntryStatus(item, item.status === "active" ? "retired" : "active")}>{item.status === "active" ? "Retirar" : "Reactivar"}</ArcButton>
          </div>},
      ]} /></div>
      {!items.length && <p>No hay entradas en este ámbito. {tab === "http" ? "Sin superficie declarada, toda ruta se clasifica como «Sin superficie declarada»." : "Declará la primera con «Nueva entrada»."}</p>}
      <div className="pagination">
        <ArcButton type="button" variant="secondary" aria-label="Entradas anteriores" disabled={page <= 0} onClick={() => setPage(page - 1)}>Anteriores</ArcButton>
        <span>{total} entradas · Página {page + 1} de {pages}</span>
        <ArcButton type="button" variant="secondary" aria-label="Entradas siguientes" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Siguientes</ArcButton>
      </div>
      {(tab === "authentication" || tab === "application") && <p className="muted">Plantillas deterministas de este ámbito: {tab === "authentication" ? "R1 «auth_failed_burst» (ráfaga de fallos) y R2 «auth_success_after_failures» (éxito tras fallos)" : "R3 «application_error_burst» (ráfaga de errores)"} — se habilitan y ajustan (umbral, ventana, agrupación) por fuente en el panel «Reglas» de cada fuente. Si una fuente no aporta los campos que la plantilla necesita, la plantilla no se activa y la fuente muestra el motivo.</p>}
      {(creating || editing) && <form className="obs-form" onSubmit={e => { e.preventDefault(); void save(description); }}>
        <h4>{editing ? `Editar entrada (crea la revisión v${(editing.revision || 1) + 1})` : "Nueva entrada"}</h4>
        {tab === "http" && <>
          <ArcInput label="Patrón de ruta" required maxLength={200} value={form.path_pattern || ""} onChange={e => setForm({...form, path_pattern: e.target.value})} placeholder="/files/ o /users/{id}" />
          <ArcSelect label="Tipo de coincidencia" value={form.match_kind || "prefix"} onValueChange={v => setForm({...form, match_kind: v})} options={[{value:"exact",label:"Exacta: solo esa ruta"},{value:"prefix",label:"Prefijo: la ruta y todo lo que cuelga de ella (debe terminar en /)"},{value:"template",label:"Plantilla: segmentos {nombre} que coinciden con un segmento"}]} />
          <ArcSelect label="Exposición" value={form.exposure || "public"} onValueChange={v => setForm({...form, exposure: v})} options={[{value:"public",label:"Pública"},{value:"authenticated",label:"Autenticada"},{value:"internal",label:"Interna"},{value:"sensitive",label:"Sensible"}]} />
          <ArcInput label="Métodos permitidos (separados por coma)" required maxLength={40} value={form.methods || ""} onChange={e => setForm({...form, methods: e.target.value})} placeholder="GET, HEAD" />
          <ArcInput label="Comportamiento esperado" maxLength={200} value={form.expected_behavior || ""} onChange={e => setForm({...form, expected_behavior: e.target.value})} />
        </>}
        {tab === "filesystem" && <>
          <ArcSelect label="Raíz allowlisted" value={form.root_alias || "demo-logs"} onValueChange={v => setForm({...form, root_alias: v})} options={[{value:"demo-logs",label:"Carpeta demo (demo-logs)"},{value:"external",label:"Datos externos (external)"}]} />
          <ArcInput label="Directorio (un nivel, vacío = la raíz)" maxLength={64} value={form.directory || ""} onChange={e => setForm({...form, directory: e.target.value})} placeholder="web" />
          <ArcSelect label="Sensibilidad" value={form.sensitivity || "expected"} onValueChange={v => setForm({...form, sensitivity: v})} options={[{value:"expected",label:"Esperada"},{value:"sensitive",label:"Sensible"}]} />
          <ArcCheckbox label="Los cambios en esta zona son esperados" checked={!!form.expected_change} onCheckedChange={next => setForm({...form, expected_change: next === true})} />
        </>}
        {(tab === "authentication" || tab === "application") && <ArcTextarea label="Comportamiento esperado" required maxLength={500} value={form.expected_behavior || ""} onChange={e => setForm({...form, expected_behavior: e.target.value})} placeholder="Qué debería pasar normalmente en este servicio" />}
        <ArcInput label="Descripción" maxLength={300} value={description} onChange={e => setDescription(e.target.value)} />
        <p className="muted">Declarar un límite no prueba que el servicio sea seguro ni habilita acciones: solo le da a Sentinel el contexto para clasificar la evidencia. Nada de expresiones regulares ni rutas del host: patrones cerrados y raíces allowlisted.</p>
        <div className="service-row-actions">
          <ArcButton type="submit" disabled={busy}>{busy ? "Guardando…" : "Guardar entrada"}</ArcButton>
          <ArcButton type="button" variant="secondary" onClick={() => { setCreating(false); setEditing(null); }}>Cancelar</ArcButton>
        </div>
      </form>}
      {history && <div className="obs-history">
        <h4>Historial de la entrada</h4>
        <ul>{history.map(rev => <li key={rev.revision}>v{rev.revision} · {rev.status === "active" ? "Activa" : "Retirada"} · {new Date(rev.created_at).toLocaleString("es-CR", {timeZone: "America/Costa_Rica"})} <code>{JSON.stringify(rev.config)}</code> {rev.revision !== history[0].revision && <ArcButton type="button" variant="secondary" disabled={busy} onClick={() => void revert(rev.revision)}>Revertir a v{rev.revision}</ArcButton>}</li>)}</ul>
        <ArcButton type="button" variant="secondary" onClick={() => setHistory(null)}>Cerrar historial</ArcButton>
      </div>}
    </>}
  </section>;
}
