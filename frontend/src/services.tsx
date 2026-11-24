import React, { useCallback, useEffect, useId, useRef, useState } from "react";
import { Switch as ArcSwitch } from "@/components/arc/switch/switch";
import { Dialog as ArcDialog, DialogContent as ArcDialogContent } from "@/components/arc/dialog/dialog";
import { Button as ArcButton } from "@/components/arc/button/button";
import { Select as ArcSelect } from "@/components/arc/select/select";
import { Input as ArcInput } from "@/components/arc/input/input";
import { Textarea as ArcTextarea } from "@/components/arc/textarea/textarea";
import { Slider as ArcSlider } from "@/components/arc/slider/slider";
import { DropdownMenu as ArcDropdownMenu } from "@/components/arc/dropdown-menu/dropdown-menu";
import { SortableDataTable as ArcTable } from "@/components/arc/sortable-data-table/sortable-data-table";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { ClassificationBadge, ObservabilityPanel } from "./observability";
import { notifyToast } from "./toast";
import { ChevronDown, ChevronRight } from "lucide-react";

export type ServiceData = Record<string, any>;
type Api = (path: string, method?: string, body?: unknown) => Promise<ServiceData>;
const serviceState = (service: ServiceData) => service.deleted_at ? "Eliminado" : service.enabled ? "Activo" : "Inactivo";
const serviceLabel = (service: ServiceData) => `${service.name}${service.deleted_at ? " (eliminado)" : !service.enabled ? " (inactivo)" : ""}`;
const errorText = (error: unknown) => error instanceof Error ? error.message : "No se pudo guardar el cambio.";
type LabResource = {value: string; label: string; rules: string[]; optional?: boolean};
const LAB_SERVICES: {value: string; label: string; system: string; protocol: string; name: string; context: string; resources: LabResource[]}[] = [
  {value: "nginx", label: "Nginx", system: "Nginx", protocol: "HTTP", name: "Nginx laboratorio VM", context: "Servidor web Nginx de la VM del laboratorio. Sus registros llegan por MCP; los códigos y las rutas son evidencia para investigar y no confirman un compromiso.", resources: [
    {value: "logs://nginx/access", label: "Nginx · accesos", rules: ["R1", "R2", "R3", "request_outside_declared_surface", "encoded_path_traversal", "ambiguous_request_normalization"]},
    {value: "logs://nginx/error", label: "Nginx · errores", rules: ["R3"]},
  ]},
  {value: "mysql", label: "MySQL", system: "MySQL", protocol: "SQL", name: "MySQL laboratorio VM", context: "Base de datos de la VM del laboratorio. El MCP lee el registro de errores y, si está disponible, el de auditoría como texto.", resources: [
    {value: "logs://mysql/error", label: "MySQL · errores", rules: ["R3"]},
    {value: "logs://mysql/audit", label: "MySQL · auditoría", rules: [], optional: true},
  ]},
  {value: "node", label: "Node.js", system: "Node.js", protocol: "HTTP", name: "Node laboratorio VM", context: "Aplicación Node.js de la VM del laboratorio (entrenamiento). Registros de aplicación y de seguridad por MCP, correlacionados por request_id.", resources: [
    {value: "logs://node/app", label: "Node.js · aplicación", rules: ["R3"]},
    {value: "logs://node/security", label: "Node.js · seguridad", rules: ["R1", "R2"]},
  ]},
  {value: "ssh", label: "OpenSSH (SSH)", system: "OpenSSH", protocol: "SSH", name: "SSH laboratorio VM", context: "Acceso SSH a la VM del laboratorio. El registro de autenticación llega por MCP: los fallos repetidos y un acceso aceptado tras varios fallos son la señal principal.", resources: [
    {value: "logs://ssh/auth", label: "SSH · autenticación", rules: ["R1", "R2"]},
  ]},
];
const LAB_RESOURCES = LAB_SERVICES.flatMap(service => service.resources);
const initialSource = () => ({kind: "folder", config: {root_alias: "demo-logs", selector: ""} as ServiceData, analysis: {system: "Sin especificar", protocol: "Sin especificar", adapter: "auto", context: "", rules: [] as ServiceData[]}, enabled: false});
const sourceHealth = (status?: string) => ({healthy: "Al día", degraded: "Revisar conexión", blocked: "Bloqueada", pending: "Sin lecturas", inactive: "Inactiva", deleted: "Retirada"} as Record<string, string>)[status || ""] || "Sin lecturas";
const sourceIssue = (code?: string) => ({mcp_lab_gap: "La continuidad se perdió; revisá la rotación y el cursor.", mcp_connection_failed: "No se pudo conectar. Revisá la red y el certificado del laboratorio.", mcp_lab_credential_required: "Agregá la credencial del MCP.", mcp_record_storage_backpressure: "La cola está llena; la lectura está pausada.", mcp_lab_page_invalid: "El MCP devolvió una respuesta inválida.", mcp_lab_metadata_invalid: "La versión o las rutas del MCP no cumplen el contrato del laboratorio.", mcp_lab_service_product_mismatch: "Este recurso corresponde a otro producto; creá un servicio separado.", mcp_lab_record_invalid: "El MCP devolvió un registro inválido."} as Record<string, string>)[code || ""] || (code ? "No se pudo leer la fuente; revisá la configuración y el servicio." : "");
const dateText = (value?: string) => value ? new Date(value).toLocaleString("es-CR", {timeZone: "America/Costa_Rica"}) : "Sin lecturas";

export function ToggleSwitch({checked, onChange, label, disabled = false}: {checked: boolean; onChange: (next: boolean) => void; label: string; disabled?: boolean}) {
  // Interruptor de Arc (Radix): mismo contrato (role=switch, nombre accesible
  // = label, onChange con el nuevo valor) que el botón propio anterior.
  return <ArcSwitch checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled} />;
}

export function ActionMenu({label, items}: {label: string; text?: string; items: {label: string; onSelect: () => void; disabled?: boolean}[]}) {
  // Menú desplegable de Arc (Radix): el disparador muestra la etiqueta y los
  // ítems conservan label/onSelect/disabled; Eliminar/Retirar van en tono
  // destructivo.
  return <ArcDropdownMenu label={label} items={items.map(item => ({...item, destructive: item.label === "Eliminar" || item.label === "Retirar fuente"}))} />;
}

export function ServicePicker({api, value, onChange, label = "Servicio", refresh = 0, emptyLabel = "Todos los servicios"}: {api: Api; value: string; onChange: (id: string) => void; label?: string; refresh?: number; emptyLabel?: string}) {
  const [items, setItems] = useState<ServiceData[]>([]), [selected, setSelected] = useState<ServiceData | null>(null), [q, setQ] = useState(""), [cursors, setCursors] = useState<(string | null)[]>([null]), [next, setNext] = useState<string | null>(null), [error, setError] = useState("");
  const id = useId(), request = useRef(0);
  useEffect(() => {
    const seq = ++request.current;
    const query = new URLSearchParams({state: "all", limit: "25", q});
    if (cursors.at(-1)) query.set("cursor", cursors.at(-1)!);
    void api("/services?" + query).then(data => {if (seq === request.current) {setItems(data.items || []); setNext(data.next_cursor || null); setError("");}}).catch(error => {if (seq === request.current) setError(errorText(error));});
    return () => {request.current++;};
  }, [api, q, cursors, refresh]);
  useEffect(() => {
    let current = true;
    if (!value) {setSelected(null); return;}
    void api("/services/" + encodeURIComponent(value)).then(data => {if (current) setSelected(data);}).catch(() => {});
    return () => {current = false;};
  }, [api, value, refresh]);
  return <div className="service-picker">
    <ArcSelect id={id} label={label} value={value || "__none__"} onValueChange={v => onChange(v === "__none__" ? "" : v)} options={[{value: "__none__", label: emptyLabel}, ...(value && !items.some(item => item.id === value) ? [{value, label: selected ? serviceLabel(selected) : "Servicio seleccionado"}] : []), ...items.map(item => ({value: item.id, label: serviceLabel(item)}))]} />
    <details className="service-picker-search"><summary>Buscar otros servicios</summary>
      <ArcInput label="Buscar servicio por nombre" value={q} onChange={event => {setQ(event.target.value); setCursors([null]);}} />
      <div className="service-picker-pages"><ArcButton type="button" variant="secondary" disabled={cursors.length === 1} onClick={() => setCursors(previous => previous.slice(0, -1))}>Anteriores</ArcButton><span>Página {cursors.length}</span><ArcButton type="button" variant="secondary" disabled={!next} onClick={() => next && setCursors(previous => [...previous, next])}>Más servicios</ArcButton></div>
    </details>
    {error && <small role="alert">{error}</small>}
  </div>;
}

const RULE_META: Record<string, {name: string; detail: string; threshold: number; window: number; severity?: string; family?: "http" | "structure"}> = {
  R1: {name: "Fallos de acceso", detail: "Autenticaciones o accesos rechazados que se repiten.", threshold: 5, window: 60},
  R2: {name: "Acceso tras fallos", detail: "Un acceso aceptado poco después de varios fallos.", threshold: 5, window: 120},
  R3: {name: "Errores HTTP o de aplicación", detail: "Errores del servidor o de la aplicación concentrados en poco tiempo.", threshold: 10, window: 30},
  request_outside_declared_surface: {name: "Solicitud fuera de la superficie declarada", detail: "Rutas o métodos fuera de los límites observables declarados del servicio (pestaña HTTP del perfil). Se evalúa solo cuando los eventos traen evidencia HTTP.", threshold: 3, window: 300, severity: "low", family: "http"},
  encoded_path_traversal: {name: "Intento de path traversal", detail: "Traversal observado en el target (../, %2e%2e o doble codificación), antes de la normalización del servidor. Es un intento: no afirma acceso.", threshold: 1, window: 300, severity: "medium", family: "http"},
  ambiguous_request_normalization: {name: "Normalización de solicitud ambigua", detail: "El target crudo y la ruta normalizada no se corresponden con una decodificación simple; la forma original no se reconstruye.", threshold: 1, window: 300, severity: "low", family: "http"},
  unexpected_structure_change: {name: "Cambio de estructura no esperado", detail: "Cuenta rutas nuevas fuera de las zonas con cambios esperados en las capturas del mapa de estructura del mismo servicio, raíz y directorio: al llegar al umbral dentro de la ventana abre una incidencia y no la duplica mientras siga activa en la ventana.", threshold: 1, window: 300, severity: "medium", family: "structure"},
  sensitive_structure_change: {name: "Cambio en zona sensible de la estructura", detail: "Cuenta rutas nuevas dentro de una zona declarada sensible en las capturas del mapa de estructura del mismo servicio, raíz y directorio: al llegar al umbral dentro de la ventana abre una incidencia y no la duplica mientras siga activa en la ventana.", threshold: 1, window: 300, severity: "high", family: "structure"},
};

const SEVERITY_OPTIONS: [string, string][] = [["low", "Baja"], ["medium", "Media"], ["high", "Alta"], ["critical", "Crítica"]];

function templateCompatible(meta: {family?: "http" | "structure"}, sourceKind?: string): boolean {
  if (!meta.family) return true;
  if (meta.family === "structure") return sourceKind === "folder";
  return true;
}

function defaultRule(id: string): ServiceData {
  const {threshold, window, severity} = RULE_META[id];
  return {id, enabled: true, threshold, window_seconds: window, ...(severity ? {severity} : {})};
}

// Reglas específicas del operador («custom:…»): un contador propio para la
// fuente — nombre libre, señal cerrada, umbral/ventana/severidad — que el
// backend evalúa igual que las plantillas (mismo contrato que
// CUSTOM_SIGNALS en backend/src/services.rs).
const CUSTOM_SIGNALS: [string, string][] = [
  ["auth.failed", "Fallos de acceso"],
  ["auth.success", "Accesos aceptados"],
  ["app.error", "Errores de aplicación"],
  ["http.suspicious", "Solicitudes HTTP sospechosas"],
  ["level.error", "Eventos con nivel error"],
  ["any", "Cualquier evento de la fuente"],
];
const customMeta = (rule: ServiceData): (typeof RULE_META)[string] => ({name: String(rule.name || rule.id), detail: `Regla específica tuya: cuenta ${(CUSTOM_SIGNALS.find(([value]) => value === rule.signal)?.[1] || String(rule.signal || "")).toLowerCase()} de esta fuente y abre una incidencia con este nombre al llegar al umbral.`, threshold: Number(rule.threshold) || 5, window: Number(rule.window_seconds) || 300, severity: String(rule.severity || "medium")});
const slugifyRule = (name: string) => name.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32) || "regla";
export function RulePicker({rules, onRules, sourceKind}: {rules: ServiceData[]; onRules: (rules: ServiceData[]) => void; sourceKind?: string}) {
  const [query, setQuery] = useState("");
  const [customOpen, setCustomOpen] = useState(false);
  const [customName, setCustomName] = useState("");
  const [customSignal, setCustomSignal] = useState("auth.failed");
  const atLimit = rules.length >= 12;
  const addCustom = () => {
    const name = customName.trim();
    if (!name || atLimit) return;
    const id = `custom:${slugifyRule(name)}-${Math.random().toString(36).slice(2, 6)}`;
    onRules([...rules, {id, name, signal: customSignal, enabled: true, threshold: 5, window_seconds: 300, severity: "medium"}]);
    setCustomName("");
    setCustomOpen(false);
    setExpanded(id);
  };
  // UI-ARC-06 (punto 14): una sola regla expandida a la vez; las que ya
  // venían guardadas arrancan COLAPSADAS y la recién agregada se expande
  // sola para configurarla sin perder el contexto.
  const [expanded, setExpanded] = useState<string | null>(null);
  const uid = useId();
  const updateRule = (id: string, patch: ServiceData) => onRules(rules.map(rule => rule.id === id ? {...rule, ...patch} : rule));
  const available = Object.keys(RULE_META).filter(id => !rules.some(rule => rule.id === id) && templateCompatible(RULE_META[id], sourceKind));
  const normalized = query.trim().toLowerCase();
  const suggestions = available.filter(id => !normalized || `${id} ${RULE_META[id].name} ${RULE_META[id].detail}`.toLowerCase().includes(normalized));
  const summaryOf = (rule: ServiceData, meta: (typeof RULE_META)[string]) => meta.family === "structure" ? `Se activa con ${rule.threshold} o más rutas nuevas en ${rule.window_seconds} segundos, sumando las capturas del mismo servicio, raíz y directorio.` : `Se activa con ${rule.threshold} o más eventos en ${rule.window_seconds} segundos.`;
  return <div className="rule-list">
    <p className="rule-list-title">Reglas de detección incorporadas</p>
    {/* UI-ARC-06 (punto 14): el buscador va PRIMERO y fijo en el DOM: las
        reglas incorporadas se listan DEBAJO, así agregar una nunca
        desplaza el input (en UI-ARC-05 las incorporadas vivían arriba y
        empujaban el buscador hacia abajo). */}
    {atLimit ? <p className="muted">Llegaste al máximo de 12 reglas por fuente.</p> : available.length > 0 ? <div className="rule-add">
      <ArcInput label="Buscar reglas para incorporar" type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Fallos, acceso, errores…" />
      {!normalized && <p className="muted">Escribí para buscar reglas y agregá solo las que esta fuente necesita; las agregadas aparecen abajo como filas colapsadas.</p>}
      {normalized && <div className="rule-suggestions">
        {suggestions.map(id => {const meta = RULE_META[id]; return <ArcButton type="button" key={id} variant="ghost" className="rule-suggestion" onClick={() => {onRules([...rules, defaultRule(id)]); setQuery(""); setExpanded(id);}}><span><strong>{id}: {meta.name}</strong><small>{meta.detail}</small></span><span className="rule-suggestion-action">+ Agregar</span></ArcButton>;})}
        {!suggestions.length && <p className="muted">Ninguna regla disponible coincide con esa búsqueda.</p>}
      </div>}
    </div> : <p className="muted">Ya incorporaste todas las reglas disponibles para este tipo de fuente.</p>}
    {!atLimit && <div className="rule-custom">
      {customOpen ? <>
        <ArcInput label="Nombre de tu regla específica" value={customName} onChange={event => setCustomName(event.target.value)} placeholder="Ej.: Gritos de ayuda en el login" maxLength={80} />
        <ArcSelect label="Qué cuenta la regla" value={customSignal} onValueChange={setCustomSignal} options={CUSTOM_SIGNALS.map(([value, label]) => ({value, label}))} />
        <p className="muted">Cuenta esa señal solo en ESTA fuente: al llegar al umbral dentro de la ventana abre una incidencia con tu nombre. El umbral, la ventana y la severidad se ajustan en la regla recién creada, abajo.</p>
        <div className="rule-custom-actions"><ArcButton type="button" onClick={addCustom} disabled={!customName.trim()}>Agregar regla específica</ArcButton><ArcButton type="button" variant="ghost" onClick={() => setCustomOpen(false)}>Cancelar</ArcButton></div>
      </> : <ArcButton type="button" variant="ghost" className="rule-suggestion" onClick={() => setCustomOpen(true)}><span><strong>Crear una regla específica</strong><small>Tu propio contador para esta fuente: nombre, señal, umbral, ventana y severidad.</small></span><span className="rule-suggestion-action">+ Crear</span></ArcButton>}
    </div>}
    <div className="rule-incorporated" aria-label="Reglas incorporadas">
      {rules.length ? rules.map(rule => {
        const isCustom = String(rule.id).startsWith("custom:");
        const meta = RULE_META[rule.id] || (isCustom ? customMeta(rule) : null);
        if (!meta) return null;
        const active = rule.enabled !== false;
        const open = expanded === rule.id && active;
        return <section key={rule.id} className="rule-card" data-active={active || undefined} data-expanded={open || undefined}>
          {/* UI-ARC-07 (punto 1): TODA la fila-cabecera es la superficie de
              toggle (el click del botón interno burbujea hasta acá y toggla
              una sola vez); el chevron es un icono de 18px en un área de
              30px (antes un glifo de texto de 7px que el click humano
              convertía en selección de texto, ver ::selection en la
              captura de Allan) y la cabecera no es seleccionable. Los
              controles internos frenan la propagación. */}
          <div className="rule-card-heading" onClick={() => setExpanded(open ? null : rule.id)}>
            <button type="button" className="rule-toggle" aria-expanded={open} aria-label={`${open ? "Colapsar" : "Configurar"} regla ${rule.id}`}>
              <span className="rule-toggle-chevron" aria-hidden="true">{open ? <ChevronDown size={18} /> : <ChevronRight size={18} />}</span>
              <span className="rule-toggle-text"><strong>{isCustom ? meta.name : `${rule.id}: ${meta.name}`}</strong><small>{summaryOf(rule, meta)}</small></span>
            </button>
            <div className="rule-card-actions" data-rule-actions onClick={event => event.stopPropagation()}><ToggleSwitch label={`${rule.id}: ${meta.name}`} checked={active} onChange={next => updateRule(rule.id, {enabled: next})} /><ArcButton type="button" variant="secondary" size="sm" aria-label={`Quitar regla ${rule.id}`} onClick={() => onRules(rules.filter(item => item.id !== rule.id))}>Quitar</ArcButton></div>
          </div>
          {!active && <p className="muted rule-inactive">Regla inactiva: no detecta. Activala para ajustar su configuración.</p>}
          {!templateCompatible(meta, sourceKind) && <p role="status">Esta plantilla no se puede habilitar en este tipo de fuente: las plantillas de estructura se configuran en las fuentes de carpeta que respaldan las raíces del mapa de estructura (demo-logs/external).</p>}
          {open && <div className="rule-options">
            <p className="muted">{meta.detail}</p>
            <div className="range-row"><ArcSlider label={`Umbral de ${rule.id}`} min={1} max={100} step={1} value={rule.threshold} onValueChange={value => updateRule(rule.id, {threshold: value as number})} /><ArcInput label={`Umbral exacto de ${rule.id}`} type="number" min={1} max={100} value={rule.threshold} onChange={event => updateRule(rule.id, {threshold: Number(event.target.value)})} /></div>
            <div className="range-row"><ArcSlider label={`Ventana de ${rule.id}`} min={5} max={600} step={5} value={rule.window_seconds} onValueChange={value => updateRule(rule.id, {window_seconds: value as number})} /><ArcInput label={`Ventana exacta de ${rule.id}`} type="number" min={1} max={600} value={rule.window_seconds} onChange={event => updateRule(rule.id, {window_seconds: Number(event.target.value)})} /></div>
            {(meta.family || isCustom) && <div className="range-row"><ArcSelect label="Severidad inicial" value={rule.severity || meta.severity || "low"} onValueChange={value => updateRule(rule.id, {severity: value})} options={SEVERITY_OPTIONS.map(([value, label]) => ({value, label}))} /></div>}
            {!meta.family && !isCustom && <div className="switch-row"><span>Condición adicional</span><ToggleSwitch label="Agregar condición" checked={!!rule.condition} onChange={next => updateRule(rule.id, {condition: next ? {field: "level", operator: "eq", value: "error"} : undefined})} /></div>}
            {rule.condition && <div className="rule-condition"><ArcSelect label="Campo" value={rule.condition.field} onValueChange={value => updateRule(rule.id, {condition: {...rule.condition, field: value}})} options={[{value:"level",label:"Nivel"},{value:"source",label:"Origen declarado"}]} /><ArcSelect label="Operador" value={rule.condition.operator} onValueChange={value => updateRule(rule.id, {condition: {...rule.condition, operator: value}})} options={[{value:"eq",label:"Igual a"},{value:"not_eq",label:"Distinto de"}]} /><ArcInput label="Valor" required maxLength={80} value={rule.condition.value} onChange={event => updateRule(rule.id, {condition: {...rule.condition, value: event.target.value}})} /></div>}
          </div>}
        </section>;
      }) : <p className="muted">Todavía no incorporaste reglas: esta fuente no detecta nada. Buscá una regla arriba y agregá solo las relevantes para no sobrecargar la vista.</p>}
    </div>
    {sourceKind !== "folder" && <p className="muted">Las plantillas de estructura (cambio no esperado / zona sensible) no se ofrecen aquí: se configuran en las fuentes de carpeta que respaldan las raíces del mapa de estructura.</p>}
  </div>;
}

function SourceFields({source, change, editing = false, lockKind = false}: {source: ServiceData; change: (source: ServiceData) => void; editing?: boolean; lockKind?: boolean}) {
  const config = source.config || {};
  const analysis = source.analysis || initialSource().analysis;
  const setAnalysis = (patch: ServiceData) => change({...source, analysis: {...analysis, ...patch}});
  return <div className="source-fields-grid">
    {!lockKind && <ArcSelect label="Tipo de fuente" value={source.kind} disabled={editing} onValueChange={value => change({...source, kind: value, enabled: false, config: value === "folder" ? {root_alias: "demo-logs", selector: ""} : {endpoint: "", resource_uri: "", synthetic: true}})} options={[{value:"folder",label:"Carpeta de logs"},{value:"mcp",label:"MCP de lectura"}]} />}
    {source.kind === "folder" ? <>
      <ArcSelect label="Origen de los registros" value={config.root_alias || "demo-logs"} disabled={editing} onValueChange={root => {
        const next = {...config, root_alias: root};
        if (root === "external") next.data_class = "real"; else delete next.data_class;
        change({...source, config: next});
      }} options={[{value:"demo-logs",label:"Demo: registros sintéticos"},{value:"external",label:"Carpeta del equipo: registros reales"}]} />
      <ArcInput label="Directorio del servicio" maxLength={64} pattern="[A-Za-z0-9_\-]*" value={config.directory || ""} placeholder="nginx (vacío para la raíz)" onChange={event => change({...source, config: {...config, directory: event.target.value}})} />
      <ArcInput label="Archivo o patrón" required maxLength={200} value={config.selector || ""} placeholder="nginx.log o nginx-*.log" onChange={event => change({...source, config: {...config, selector: event.target.value}})} />
      {config.root_alias === "external" ? <p className="muted">Elegí un directorio dentro de la carpeta del equipo que el operador ya montó en modo de solo lectura. Guardar esta fuente no monta carpetas. Los registros reales no se envían al proveedor por defecto.</p> : <p className="muted">Un directorio de primer nivel dentro del volumen de demo. Sin rutas del host, enlaces ni subcarpetas anidadas.</p>}
    </> : <>
      <ArcSelect label="Modo MCP" value={config.mode === "incremental_lab" ? "incremental_lab" : "snapshot"} disabled={editing} onValueChange={value => change({...source, config: value === "incremental_lab" ? {endpoint: config.endpoint || "", resource_uri: "logs://nginx/access", synthetic: false, mode: "incremental_lab", poll_seconds: 5} : {endpoint: config.endpoint || "", resource_uri: "", synthetic: true}})} options={[{value:"snapshot",label:"Snapshot sintético"},{value:"incremental_lab",label:"Laboratorio incremental"}]} />
      <ArcInput label="Endpoint MCP" required type="url" value={config.endpoint || ""} placeholder="https://servidor-autorizado.example/mcp" onChange={event => change({...source, config: {...config, endpoint: event.target.value}})} />
      {config.mode === "incremental_lab" ? <><ArcSelect label="Recurso" value={config.resource_uri || "logs://nginx/access"} onValueChange={value => change({...source, config: {...config, resource_uri: value}})} options={LAB_RESOURCES} /><ArcInput label="Intervalo de consulta en segundos" type="number" min={5} max={300} required value={config.poll_seconds ?? 5} onChange={event => change({...source, config: {...config, poll_seconds: Number(event.target.value)}})} /></> : <ArcInput label="Recurso de logs" required value={config.resource_uri || ""} placeholder="logs://servicio/archivo" onChange={event => change({...source, config: {...config, resource_uri: event.target.value}})} />}
      <ArcInput label="Credencial MCP" type="password" required={config.mode === "incremental_lab" && !source.has_credential} autoComplete="new-password" value={source.credential || ""} placeholder={source.has_credential ? "Configurada; dejar vacío para conservar" : config.mode === "incremental_lab" ? "Obligatoria en el laboratorio" : "Opcional"} onChange={event => change({...source, credential: event.target.value})} />
      {config.mode === "incremental_lab" && <ArcTextarea label="Certificado CA (PEM, opcional)" value={config.ca_pem || ""} placeholder="Dejalo vacío para usar la CA del paquete (lab/lab-ca.pem); pegá una CA personalizada si este laboratorio usa otra" onChange={event => change({...source, config: {...config, ca_pem: event.target.value.trim() ? event.target.value.trim() : undefined}})} />}
      <p className="muted">{config.mode === "incremental_lab" ? "El endpoint debe ser HTTPS en el puerto 443 y pertenecer a la red aislada del laboratorio (/mcp). La versión llega desde el archivo de estado del servicio; agregá cada recurso de logs como fuente. Los registros reales no se envían a proveedores de IA." : "Recursos sintéticos de lectura en un servidor autorizado."} La conexión usa el certificado CA configurado en Sentinel y una credencial MCP. La IA no recibe herramientas.</p>
    </>}
    <fieldset className="source-analysis"><legend>Interpretación de esta fuente</legend>
      <ArcInput label="Sistema de la fuente" required maxLength={80} value={analysis.system} onChange={event => setAnalysis({system: event.target.value})} placeholder="Nginx u OpenSSH" />
      <ArcInput label="Protocolo de la fuente" required maxLength={80} value={analysis.protocol} onChange={event => setAnalysis({protocol: event.target.value})} placeholder="HTTP o SSH" />
      <ArcSelect label="Adaptador" value={analysis.adapter} onValueChange={value => setAnalysis({adapter: value})} options={[{value:"auto",label:"Detectar formato conocido"},{value:"sentinel-json",label:"Sentinel JSON"},{value:"native-text",label:"Texto nativo conocido"},{value:"plain-text",label:"Solo texto, sin campos estructurados"}]} />
      <ArcTextarea label="Contexto para la IA" maxLength={2000} value={analysis.context} onChange={event => setAnalysis({context: event.target.value})} placeholder="Qué registra esta fuente y qué datos no conserva" />
      <p className="muted">Este contexto se trata como dato. No modifica reglas de seguridad ni instrucciones del modelo.</p>
      <RulePicker rules={analysis.rules} onRules={rules => setAnalysis({rules})} sourceKind={source.kind} />
    </fieldset>
  </div>;
}

function SourceRow({api, serviceId, source, onSaved, onDirty, onCancelEdit}: {api: Api; serviceId: string; source: ServiceData; onSaved: () => void; onDirty: () => void; onCancelEdit?: () => void}) {
  const [editing, setEditing] = useState(false), [form, setForm] = useState(source), [rulesOpen, setRulesOpen] = useState(false), [rulesForm, setRulesForm] = useState<ServiceData[]>(source.analysis?.rules || []), [busy, setBusy] = useState(false), [error, setError] = useState(""), [removing, setRemoving] = useState(false), [checking, setChecking] = useState(false), [checkResult, setCheckResult] = useState<ServiceData | null>(null), [preview, setPreview] = useState<ServiceData | null>(null), [previewing, setPreviewing] = useState(false), [history, setHistory] = useState<ServiceData[] | null>(null), [historyNext, setHistoryNext] = useState<number | null>(null), [restoreVersion, setRestoreVersion] = useState<number | null>(null);
  async function loadHistory(before?: number) {
    setError("");
    try {const query = new URLSearchParams({limit: "20"}); if (before) query.set("before", String(before)); const result = await api(`/sources/${source.id}/revisions?` + query); setHistory(items => before ? [...(items || []), ...(result.items || [])] : result.items || []); setHistoryNext(result.next_before || null);} catch (error) {setError(errorText(error));notifyToast("error","No se pudo cargar el historial de la fuente",errorText(error));}
  }
  async function check() {
    setChecking(true); setError(""); setCheckResult(null);
    try {
      const result = await api(`/sources/${source.id}/check`, "POST", {});
      if (result.readable !== true || (source.kind === "folder" && (!Number.isSafeInteger(result.matching_files) || result.matching_files < 0))) throw new Error(result.connection_attempted ? "Se intentó conectar, pero el recurso no se pudo leer. Revisá endpoint, certificado, credencial y recurso." : "No se pudo comprobar la lectura de la fuente.");
      setCheckResult(result);
      notifyToast("success","Lectura de fuente correcta",source.kind === "folder" ? `${result.matching_files} archivo(s) disponible(s); no se envió contenido al proveedor.` : `Recurso leído (${result.bytes} bytes).`);
    } catch (error) {setError(errorText(error));notifyToast("error","La fuente no se pudo leer",errorText(error));} finally {setChecking(false);}
  }
  async function mutate(method: string, body: ServiceData) {
    setBusy(true); setError("");
    try {await api(`/sources/${source.id}`, method, {expected_version: source.version, ...body}); setEditing(false); setRemoving(false); setRulesOpen(false); onSaved(); notifyToast("success", method === "DELETE" ? "Fuente retirada" : "Fuente actualizada", "La evidencia y el historial anteriores se conservan.");} catch (error) {setError(errorText(error));notifyToast("error","No se pudo actualizar la fuente",errorText(error));} finally {setBusy(false);}
  }
  return <li className="service-source">
    <div className="service-source-heading"><div><strong>{source.kind === "mcp" ? source.config?.mode === "incremental_lab" ? "MCP · laboratorio" : "MCP" : source.config?.root_alias === "external" ? "Carpeta del equipo · registros reales" : "Carpeta de demo · registros sintéticos"}</strong><p>{source.kind === "mcp" ? source.config?.resource_uri : [source.config?.directory, source.config?.selector].filter(Boolean).join("/")}</p><small>{source.deleted_at ? "Retirada" : source.enabled ? "Activa" : "Inactiva"} · {sourceHealth(source.status)}</small><small> · Prueba: {source.last_check ? source.last_check.source_version === source.version ? source.last_check.result?.readable ? "lectura correcta" : "lectura fallida" : "repetir tras el cambio" : "pendiente"}</small>{source.last_check?.result?.service && <p className="muted">{source.last_check.result.service.product} · versión {source.last_check.result.service.version || "pendiente"}{source.last_check.result.service.routes?.length ? ` · rutas: ${source.last_check.result.service.routes.join(", ")}` : ""}</p>}{sourceIssue(source.last_error_code) && <p role="status">{sourceIssue(source.last_error_code)}</p>}<p className="source-rules-summary">Reglas: {(source.analysis?.rules || []).length ? (source.analysis.rules as ServiceData[]).map((rule: ServiceData) => `${String(rule.id).startsWith("custom:") && rule.name ? rule.name : rule.id} ${rule.enabled === false ? "inactiva" : "activa"}`).join(" · ") : "sin reglas incorporadas"}</p></div>
      {!source.deleted_at && <div className="service-row-actions"><ArcButton type="button" variant="secondary" disabled={busy || checking} onClick={() => void check()}>{checking ? "Comprobando…" : "Comprobar lectura"}</ArcButton><ArcButton type="button" variant="secondary" disabled={busy || previewing} onClick={() => {setPreviewing(true); setError(""); void api(`/sources/${source.id}/rules/preview`, "POST", {}).then(result => {setPreview(result);notifyToast("success","Prueba de reglas completada",`${result.inspected_events} evento(s) revisados; no se crearon incidencias ni se llamó a la IA.`);}).catch(error => {setError(errorText(error));notifyToast("error","La prueba de reglas falló",errorText(error));}).finally(() => setPreviewing(false));}}>{previewing ? "Probando…" : "Probar reglas"}</ArcButton><ArcButton type="button" variant="secondary" disabled={busy} onClick={() => {setRulesForm(source.analysis?.rules || []); setRulesOpen(!rulesOpen); setEditing(false); setRemoving(false);}}>Reglas ({(source.analysis?.rules || []).length})</ArcButton><ArcButton type="button" variant="secondary" disabled={busy} onClick={() => {setForm(source); setEditing(!editing); setRemoving(false); setRulesOpen(false);}}>Editar fuente</ArcButton><ToggleSwitch label={source.enabled ? "Desactivar fuente" : "Activar fuente"} checked={!!source.enabled} disabled={busy} onChange={() => void mutate("PUT", {kind: source.kind, config: source.config, enabled: !source.enabled})} /><ActionMenu label="Acciones" items={[{label: history ? "Actualizar historial" : "Ver historial", onSelect: () => void loadHistory()}, {label: "Retirar fuente", onSelect: () => {setRemoving(true); setEditing(false);}}]} /></div>}
    </div>
    {editing && <form onSubmit={event => {event.preventDefault(); void mutate("PUT", {kind: form.kind, config: form.config, analysis: form.analysis, enabled: form.enabled, ...(form.credential ? {credential: form.credential} : {})});}}><SourceFields source={form} change={value => {setForm(value); onDirty();}} editing /><div className="service-row-actions"><ArcButton disabled={busy}>Guardar fuente</ArcButton><ArcButton type="button" variant="secondary" disabled={busy} onClick={() => {setEditing(false); onCancelEdit?.();}}>Cancelar edición de fuente</ArcButton></div></form>}
    {rulesOpen && <div className="source-rules-panel"><RulePicker rules={rulesForm} onRules={next => {setRulesForm(next); onDirty();}} sourceKind={source.kind} /><div className="service-row-actions"><ArcButton type="button" disabled={busy} onClick={() => void mutate("PUT", {kind: source.kind, config: source.config, analysis: {...(source.analysis || {}), rules: rulesForm}, enabled: source.enabled})}>Guardar reglas</ArcButton><ArcButton type="button" variant="secondary" disabled={busy} onClick={() => {setRulesOpen(false); onCancelEdit?.();}}>Cancelar reglas</ArcButton></div></div>}
    {removing && <div className="service-confirm"><p>Retirar esta fuente detiene nuevas lecturas. Se conserva su evidencia y su historial.</p><ArcButton type="button" disabled={busy} onClick={() => void mutate("DELETE", {})}>Confirmar retiro</ArcButton><ArcButton type="button" variant="secondary" disabled={busy} onClick={() => setRemoving(false)}>Cancelar retiro</ArcButton></div>}
    {checkResult && <div role="status" className="source-check"><p>{source.kind === "folder" ? `${checkResult.matching_files} archivos disponibles` : `Recurso ${checkResult.resource_uri} leído (${checkResult.bytes} bytes)`}{checkResult.limited ? " (resultado limitado)" : ""}. No se envió contenido al proveedor.</p><p>Formato observado: {checkResult.interpretation?.format || "sin identificar"}. Campos: {checkResult.interpretation?.fields?.join(", ") || "ninguno"}.</p>{checkResult.service && <p>Servicio: {checkResult.service.id} · {checkResult.service.product} · versión {checkResult.service.version || "no disponible"} (estado del servicio){checkResult.service.routes?.length ? ` · rutas: ${checkResult.service.routes.join(", ")}` : ""}.</p>}<details><summary>Ver muestra redactada</summary><pre>{checkResult.sample || "Sin contenido"}</pre></details></div>}
    {preview && <div role="status" className="source-check"><p>Vista previa: {preview.inspected_events} eventos revisados{preview.limited ? " (límite de 500)" : ""}. No se crearon incidencias ni se llamó a la IA.</p>{preview.rules?.map((rule: ServiceData) => <p key={rule.rule_id}>{rule.name || rule.rule_id}: {rule.match_count} coincidencias entre {rule.candidates} candidatos; umbral {rule.threshold} en {rule.window_seconds} segundos. {rule.matches?.length ? `IDs: ${rule.matches.map((item: ServiceData) => item.event_id).join(", ")}` : "Sin coincidencias."}</p>)}</div>}
    {history && <section className="source-history" aria-label="Historial de interpretación"><h4>Historial de interpretación y reglas</h4><ul>{history.map(revision => <li key={revision.version}>v{revision.version} · {revision.analysis?.system} / {revision.analysis?.protocol} · {dateText(revision.created_at)} {revision.version !== source.version && <ArcButton type="button" variant="secondary" onClick={() => setRestoreVersion(revision.version)}>Elegir v{revision.version}</ArcButton>}</li>)}</ul>{historyNext && <ArcButton type="button" variant="secondary" onClick={() => void loadHistory(historyNext)}>Más versiones</ArcButton>}{restoreVersion && <div className="service-confirm"><p>Restaurar la interpretación y las reglas de v{restoreVersion} crea una revisión nueva. La fuente y su evidencia permanecen.</p><ArcButton type="button" disabled={busy} onClick={() => {setBusy(true); setError(""); void api(`/sources/${source.id}/restore`, "POST", {expected_version: source.version, restore_version: restoreVersion}).then(() => {setRestoreVersion(null); onSaved();notifyToast("success","Interpretación restaurada",`Se creó una revisión nueva a partir de v${restoreVersion}.`);}).catch(error => {setError(errorText(error));notifyToast("error","No se pudo restaurar la interpretación",errorText(error));}).finally(() => setBusy(false));}}>Confirmar restauración</ArcButton><ArcButton type="button" variant="secondary" onClick={() => setRestoreVersion(null)}>Cancelar</ArcButton></div>}</section>}
    {error && <p role="alert">{error}</p>}
    <span className="visually-hidden">Servicio {serviceId}</span>
  </li>;
}

const SOFTWARE_PRESETS: {value: string; label: string}[] = [
  {value: "apache:http_server", label: "Apache HTTP Server"},
  {value: "nginx:nginx", label: "Nginx (CPE histórico)"},
  {value: "f5:nginx", label: "Nginx (F5)"},
  {value: "openbsd:openssh", label: "OpenSSH"},
  {value: "openssl:openssl", label: "OpenSSL"},
  {value: "php:php", label: "PHP"},
  {value: "postgresql:postgresql", label: "PostgreSQL"},
  {value: "oracle:mysql", label: "MySQL"},
  {value: "nodejs:node.js", label: "Node.js"},
  {value: "mariadb:mariadb", label: "MariaDB"},
  {value: "wordpress:wordpress", label: "WordPress"},
];
export function CvePanel({api, service}: {api: Api; service: ServiceData}) {
  const [data, setData] = useState<ServiceData | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [query, setQuery] = useState(""), [severity, setSeverity] = useState(""), [onlyAffects, setOnlyAffects] = useState(false), [sort, setSort] = useState("severity"), [page, setPage] = useState(0), [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const load = useCallback(async () => {setData(await api(`/services/${service.id}/cve`));}, [api, service.id]);
  useEffect(() => {void load().catch(err => setError(errorText(err)));}, [load]);
  useEffect(() => {setPage(0);}, [query, severity, onlyAffects, sort, data]);
  async function run() {
    setBusy(true); setError("");
    try {const next=await api(`/services/${service.id}/cve-checks`, "POST", {});setData(next);notifyToast(next.check?.state === "completed" ? "success" : "warning","Chequeo CVE terminado",next.check?.state === "completed" ? `${next.check.affecting_count} CVE afectan a ${service.name}.` : "La consulta a NVD no se completó; revisá el detalle.");}
    catch (err) {setError(errorText(err));notifyToast("error","La comprobación CVE falló",errorText(err)); void load().catch(() => {});}
    finally {setBusy(false);}
  }
  function toggleExpanded(id: string) {setExpanded(prev => {const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next;});}
  function exportJson() {
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: "application/json"});
    const url = URL.createObjectURL(blob); const a = document.createElement("a");
    a.href = url; a.download = `cve-${service.name}.json`; a.click(); URL.revokeObjectURL(url);
  }
  const check = data?.check, findings: ServiceData[] = data?.findings || [], history: ServiceData[] = data?.history || [];
  const rank = (value: string) => ({critical: 4, high: 3, medium: 2, low: 1}[value] || 0);
  const filtered = findings.filter(f => (!onlyAffects || f.affects) && (!severity || f.severity === severity) && (!query || (f.cve_id + " " + (f.summary || "")).toLowerCase().includes(query.toLowerCase())));
  const sorted = [...filtered].sort((a, b) => sort === "recent" ? String(b.published || "").localeCompare(String(a.published || "")) : sort === "score" ? Number(b.base_score || 0) - Number(a.base_score || 0) : (rank(b.severity) - rank(a.severity)) || (Number(b.base_score || 0) - Number(a.base_score || 0)));
  const pageSize = 10, pages = Math.max(1, Math.ceil(sorted.length / pageSize)), pageItems = sorted.slice(page * pageSize, page * pageSize + pageSize);
  const affecting = findings.filter(f => f.affects);
  const sevCounts = ["critical", "high", "medium", "low"].map(name => ({name, n: affecting.filter(f => f.severity === name).length})).filter(x => x.n > 0);
  return <section className="service-sources cve-panel" aria-labelledby="cve-heading">
    <div className="list-heading"><h3 id="cve-heading">Vulnerabilidades (CVE)</h3><div className="cve-actions">{check && <ArcButton type="button" variant="secondary" onClick={exportJson}>Exportar JSON</ArcButton>}{service.software_product && !service.deleted_at && <ArcButton type="button" disabled={busy} onClick={() => void run()}>{busy ? "Consultando NVD…" : "Comprobar ahora"}</ArcButton>}</div></div>
    {!service.software_product && <p className="muted">Este servicio no tiene versión confirmada, así que el detector no consulta NVD por él. En una fuente de carpeta, la versión se declara manualmente en el formulario de arriba (sección «Software monitoreado»); en una fuente MCP de laboratorio, la versión llega con el estado del servicio en cada lectura: es el version.json que el propio servicio publica en su directorio (procedencia «vía MCP»). Los banners de la evidencia son solo sugerencias: nunca se aplican automáticamente.</p>}
    {service.software_product && <>
      <p className="muted">Software: <strong>{service.software_product}</strong> versión <strong>{service.software_version}</strong> ({service.software_origin === "mcp" ? "publicada por el propio servicio vía MCP (version.json)" : service.software_origin === "banner" ? "adoptada desde banners por el ciclo automático anterior; ya no se adoptan banners y esta procedencia no cuenta como versión confirmada para el chequeo diario" : "declarado por el operador"}). Fuente: NVD (NIST), consulta del backend; el veredicto «te afecta» compara tu versión con los rangos oficiales, sin IA y sin ejecutar ninguna herramienta.</p>
      {error && <p role="alert">{error}</p>}
      {!check && !error && (data?.previous_check ? <p><strong>Pendiente de comprobar:</strong> la versión actual ({service.software_product} {service.software_version}) todavía no se consultó. El último chequeo fue para {data.previous_check.product} {data.previous_check.version} ({dateText(data.previous_check.checked_at)}) y queda en el historial; sus hallazgos no cuentan como vigentes. Ejecutá «Comprobar ahora» o esperá el chequeo diario.</p> : <p>Todavía no hay comprobaciones. Ejecutá «Comprobar ahora» o activá el chequeo diario en Ajustes.</p>)}
      {check && check.state === "failed" && <p role="alert">La última comprobación falló: {check.error || "fuente no disponible"} ({dateText(check.checked_at)}).</p>}
      {check && check.state === "completed" && <>
        <p role="status">Última comprobación: {dateText(check.checked_at)} · {check.total_reported} CVE revisados · <strong>{check.affecting_count} te afectan</strong>{findings.length < check.total_reported ? ` · se guardaron los primeros ${findings.length}` : ""}.</p>
        {sevCounts.length > 0 && <div className="cve-sevbar" role="img" aria-label={"Distribución por severidad de los que te afectan: " + sevCounts.map(x => `${x.name} ${x.n}`).join(", ")}>{sevCounts.map(x => <span key={x.name} className={`severity-${x.name}`} style={{flexGrow: x.n}}>{x.name} · {x.n}</span>)}</div>}
        <div className="cve-toolbar">
          <ArcInput label="Buscar" type="search" placeholder="CVE o texto…" value={query} onChange={event => setQuery(event.target.value)} />
          <ArcSelect label="Severidad" value={severity || "__all__"} onValueChange={v => setSeverity(v === "__all__" ? "" : v)} options={[{value:"__all__",label:"Todas"},{value:"critical",label:"Crítica"},{value:"high",label:"Alta"},{value:"medium",label:"Media"},{value:"low",label:"Baja"},{value:"unknown",label:"Sin puntaje"}]} />
          <ArcSelect label="Orden" value={sort} onValueChange={setSort} options={[{value:"severity",label:"Más graves primero"},{value:"recent",label:"Más recientes"},{value:"score",label:"Mayor puntaje CVSS"}]} />
          <div className="switch-row"><span>Solo los que me afectan</span><ToggleSwitch label="Solo los que me afectan" checked={onlyAffects} onChange={setOnlyAffects} /></div>
          <ArcButton type="button" variant="secondary" onClick={() => {setQuery(""); setSeverity(""); setOnlyAffects(false); setSort("severity");}}>Limpiar filtros</ArcButton>
        </div>
        {!sorted.length && <p>No hay hallazgos con esos filtros.</p>}
        <ul className="cve-findings">{pageItems.map(f => <li key={f.id} className="cve-finding" data-severity={f.severity} data-affects={f.affects || undefined}>
          <div className="cve-finding-head"><span className={`severity-pill severity-${f.severity}`}>{f.severity}{f.base_score != null ? ` ${Number(f.base_score).toFixed(1)}` : ""}</span><a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer">{f.cve_id}</a><span className={f.affects ? "cve-affects" : "muted"}>{f.affects ? "Te afecta" : "No te afecta"}</span>{f.published && <span className="muted">{dateText(f.published)}</span>}</div>
          {f.affected_range && <p className="muted">Versiones afectadas según NVD: {f.affected_range}.</p>}
          {f.affects && f.fixed_version && <p><strong>Qué hacer:</strong> actualizá a {f.fixed_version} o superior siguiendo el aviso del proveedor. Sentinel no aplica cambios; la remediación la hace una persona.</p>}
          {f.summary && <><p className={expanded.has(f.id) ? undefined : "cve-summary"}>{f.summary}</p><ArcButton type="button" variant="secondary" onClick={() => toggleExpanded(f.id)}>{expanded.has(f.id) ? "Ver menos" : "Ver descripción completa"}</ArcButton></>}
          {Array.isArray(f.refs) && f.refs.length > 0 && <p className="cve-refs">Referencias: {f.refs.slice(0, 3).map((r: string, i: number) => <span key={r}>{i > 0 ? " · " : ""}<a href={r} target="_blank" rel="noreferrer">[{i + 1}]</a></span>)}</p>}
        </li>)}</ul>
        {sorted.length > pageSize && <nav className="cve-pages" aria-label="Páginas de hallazgos CVE"><ArcButton type="button" variant="secondary" disabled={page === 0} onClick={() => setPage(value => value - 1)}>Anteriores</ArcButton><span>{sorted.length} hallazgos · Página {page + 1} de {pages}</span><ArcButton type="button" variant="secondary" disabled={page >= pages - 1} onClick={() => setPage(value => value + 1)}>Siguientes</ArcButton></nav>}
      </>}
      {history.length > 1 && <details className="cve-history"><summary>Historial de comprobaciones ({history.length})</summary><ul>{history.map(h => <li key={h.id}>{dateText(h.checked_at)} · {h.state === "completed" ? `${h.total_reported} CVE revisados · ${h.affecting_count} te afectan` : `Falló: ${h.error || "fuente no disponible"}`} · {h.product} {h.version}</li>)}</ul></details>}
    </>}
  </section>;
}

export function StructurePanel({api, service}: {api: Api; service: ServiceData}) {
  const [data, setData] = useState<ServiceData | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [rootAlias, setRootAlias] = useState("demo-logs"), [directory, setDirectory] = useState("");
  const load = useCallback(async () => {setData(await api(`/services/${service.id}/structure`));}, [api, service.id]);
  useEffect(() => {void load().catch(err => setError(errorText(err)));}, [load]);
  async function capture() {
    setBusy(true); setError("");
    try {await api(`/services/${service.id}/structure/captures`, "POST", {root_alias: rootAlias, directory: directory.trim()}); await load();notifyToast("success","Mapa de estructura capturado","Se comparó con la captura anterior; el diff queda visible en el panel.");}
    catch (err) {setError(errorText(err));notifyToast("error","No se pudo capturar el mapa",errorText(err));}
    finally {setBusy(false);}
  }
  const roots: ServiceData[] = data?.roots || [], history: ServiceData[] = data?.history || [];
  const diffList = (root: ServiceData, key: string): ServiceData[] => Array.isArray(root.diff?.[key]) ? root.diff[key] : [];
  return <section className="service-sources structure-panel" aria-labelledby="structure-heading">
    <div className="list-heading"><h3 id="structure-heading">Mapa de estructura (solo rutas)</h3></div>
    <p className="muted">El esqueleto del sistema: carpetas y nombres de archivo con tamaño, fecha y permisos. El backend solo lista y lee metadatos: <strong>nunca abre un archivo</strong>, no calcula hashes ni sigue enlaces. Los nombres con pinta de secreto (.env, claves) ni siquiera se listan. Cada captura se compara con la anterior de la misma raíz: un archivo nuevo en una carpeta de subidas tras un ataque es un indicio para que una persona lo verifique; no es un veredicto.</p>
    {error && <p role="alert">{error}</p>}
    {!service.deleted_at && <div className="cve-toolbar">
      <ArcSelect label="Raíz" value={rootAlias} onValueChange={setRootAlias} options={[{value:"demo-logs",label:"Carpeta demo (demo-logs)"},{value:"external",label:"Datos externos (external)"}]} />
      <ArcInput label="Directorio" maxLength={64} placeholder="www" value={directory} onChange={event => setDirectory(event.target.value)} />
      <ArcButton type="button" disabled={busy} onClick={() => void capture()}>{busy ? "Capturando…" : "Capturar mapa"}</ArcButton>
    </div>}
    {!roots.length && !error && <p>Todavía no hay capturas. Capturá el mapa antes del ataque del taller y repetilo después: el diff muestra qué rutas aparecieron, desaparecieron o cambiaron.</p>}
    {roots.map(root => <div key={root.id} className="structure-root">
      <p role="status"><strong>{root.root_alias}{root.directory ? ` / ${root.directory}` : ""}</strong> · {root.node_count} rutas · {dateText(root.created_at)}{root.truncated ? " · mapa truncado por límite de tamaño" : ""}</p>
      {root.diff_source === "recomputed" && <p className="muted">Captura histórica: el diff se recalculó desde los nodos guardados; no conserva clasificaciones de detección.</p>}
      {root.diff?.first_capture ? <p className="muted">Primera captura de esta raíz: sirve de línea base para comparar la próxima.</p> : <>
        {diffList(root, "added").length > 0 && <><h4>Rutas nuevas ({diffList(root, "added").length})</h4><ul className="structure-diff added">{diffList(root, "added").slice(0, 20).map((n: ServiceData) => <li key={n.path}><code>{n.path}</code> <span className="muted">({n.kind === "dir" ? "carpeta" : n.kind === "link" ? "enlace" : "archivo"})</span>{n.classification && <ClassificationBadge value={n.classification} />}</li>)}</ul>{diffList(root, "added").length > 20 && <p className="muted">…y {diffList(root, "added").length - 20} más.</p>}</>}
        {diffList(root, "removed").length > 0 && <><h4>Rutas que desaparecieron ({diffList(root, "removed").length})</h4><ul className="structure-diff removed">{diffList(root, "removed").slice(0, 20).map((n: ServiceData) => <li key={n.path}><code>{n.path}</code></li>)}</ul></>}
        {diffList(root, "changed").length > 0 && <><h4>Rutas que cambiaron ({diffList(root, "changed").length})</h4><ul className="structure-diff changed">{diffList(root, "changed").slice(0, 20).map((n: ServiceData) => <li key={n.path}><code>{n.path}</code> <span className="muted">tamaño {n.from?.size ?? "—"} → {n.to?.size ?? "—"}</span></li>)}</ul></>}
        {diffList(root, "added").length === 0 && diffList(root, "removed").length === 0 && diffList(root, "changed").length === 0 && <p className="muted">Sin cambios contra la captura anterior: el esqueleto está igual.</p>}
      </>}
      <details><summary>Ver rutas ({(root.nodes || []).length})</summary><ul className="structure-tree">{(root.nodes || []).slice(0, 200).map((n: ServiceData) => <li key={n.path}><code>{n.path}</code> <span className="muted">{n.kind === "dir" ? "carpeta" : n.kind === "link" ? "enlace" : n.kind === "file" ? `archivo · ${n.size} B` : n.kind} · permisos {n.mode}</span></li>)}</ul>{(root.nodes || []).length > 200 && <p className="muted">Se muestran las primeras 200 rutas.</p>}</details>
    </div>)}
    {history.length > 1 && <details className="cve-history"><summary>Historial de capturas ({history.length})</summary><ul>{history.map(h => <li key={h.id}>{dateText(h.created_at)} · {h.root_alias}{h.directory ? ` / ${h.directory}` : ""} · {h.node_count} rutas{h.truncated ? " · truncado" : ""}</li>)}</ul></details>}
  </section>;
}
export function ServiceCatalog({api, refresh = 0}: {api: Api; refresh?: number}) {
  const [items, setItems] = useState<ServiceData[]>([]), [q, setQ] = useState(""), [state, setState] = useState(""), [kind, setKind] = useState(""), [system, setSystem] = useState(""), [protocol, setProtocol] = useState(""), [sourceState, setSourceState] = useState(""), [size, setSize] = useState(10), [cursors, setCursors] = useState<(string | null)[]>([null]), [next, setNext] = useState<string | null>(null), [total, setTotal] = useState(0), [unassigned, setUnassigned] = useState(0), [unresolvedRules, setUnresolvedRules] = useState(0), [loading, setLoading] = useState(true), [error, setError] = useState(""), [notice, setNotice] = useState(""), [reload, setReload] = useState(0), [toggling, setToggling] = useState<string | null>(null);
  const [modal, setModal] = useState<"create" | "edit" | "delete" | null>(null), [service, setService] = useState<ServiceData | null>(null), [form, setForm] = useState({name: "", description: "", context: "", enabled: true, software_product: "", software_version: ""}), [source, setSource] = useState<ServiceData>(initialSource), [withSource, setWithSource] = useState(true), [sourceKind, setSourceKind] = useState<"folder" | "mcp" | null>(null), [sources, setSources] = useState<ServiceData[]>([]), [sourceCursors, setSourceCursors] = useState<(string | null)[]>([null]), [sourceNext, setSourceNext] = useState<string | null>(null), [sourceTotal, setSourceTotal] = useState(0), [saving, setSaving] = useState(false), [modalError, setModalError] = useState(""), [dirty, setDirty] = useState(false), [sourcesDirty, setSourcesDirty] = useState(false), [discard, setDiscard] = useState(false);
  const confirmation = useRef<HTMLDivElement>(null);
  const [createMode, setCreateMode] = useState<"folder" | "mcp">("folder"), [labEndpoint, setLabEndpoint] = useState("https://192.168.122.210/mcp"), [labToken, setLabToken] = useState(""), [labCa, setLabCa] = useState(""), [labCaChoice, setLabCaChoice] = useState<"bundled" | "custom">("bundled"), [labBusy, setLabBusy] = useState(false), [labError, setLabError] = useState(""), [labResults, setLabResults] = useState<string[]>([]);
  const [labServiceType, setLabServiceType] = useState("all");
  const [labIncludeAudit, setLabIncludeAudit] = useState(false);
  const [labRuleDrafts, setLabRuleDrafts] = useState<Partial<Record<string, ServiceData[]>>>({});
  const [labChecking, setLabChecking] = useState(false);
  const [labAvailable, setLabAvailable] = useState<string[] | null>(null);
  const [labCheckError, setLabCheckError] = useState("");
  const labServices = LAB_SERVICES
    .filter(def => labServiceType === "all" || def.value === labServiceType)
    .map(def => ({...def, resources: def.resources.filter(resource => !resource.optional || labIncludeAudit)}));
  const labResources = labServices.flatMap(def => def.resources);
  const labMissing = labAvailable ? labResources.filter(resource => !labAvailable.includes(resource.value)) : [];
  const labCaReady = labCaChoice === "custom" ? Boolean(labCa.trim()) : true;
  const rulesFor = (resource: LabResource) => labRuleDrafts[resource.value] ?? resource.rules.map(defaultRule);
  const trigger = useRef<HTMLElement | null>(null), request = useRef(0), key = useRef("");
  // Solo la primera carga muestra «Cargando…»: los refrescos por SSE no deben
  // parpadear la tabla ni mover la paginación.
  const loaded = useRef(false);
  const load = useCallback(async () => {
    const seq = ++request.current; if (!loaded.current) setLoading(true);
    const query = new URLSearchParams({limit: String(size), q});
    if (state) query.set("state", state); if (kind) query.set("source_kind", kind); if (system) query.set("system", system); if (protocol) query.set("protocol", protocol); if (sourceState) query.set("source_state", sourceState); if (cursors.at(-1)) query.set("cursor", cursors.at(-1)!);
    try {const result = await api("/services?" + query); if (seq === request.current) {setItems(result.items || []); setNext(result.next_cursor || null); setTotal(result.total_count || 0); setUnassigned(result.unassigned_records || 0); setUnresolvedRules(result.unresolved_rules || 0); setError("");}} catch (error) {if (seq === request.current) setError(errorText(error));} finally {if (seq === request.current) {loaded.current = true; setLoading(false);}}
  }, [api, q, state, kind, system, protocol, sourceState, size, cursors]);
  useEffect(() => {void load(); return () => {request.current++;};}, [load, reload, refresh]);
  const resetPage = () => setCursors([null]);
  const close = useCallback(() => {if (saving) return; if ((dirty || sourcesDirty) && !discard) {setDiscard(true); return;} setDirty(false); setSourcesDirty(false); setDiscard(false); setModal(null);}, [saving, dirty, sourcesDirty, discard]);
  useEffect(() => {if (discard) {confirmation.current?.scrollIntoView({block: "nearest"}); confirmation.current?.focus();}}, [discard]);
  const loadSources = useCallback(async (id: string, cursor?: string | null) => {
    const query = new URLSearchParams({limit: "10"}); if (cursor) query.set("cursor", cursor);
    const data = await api(`/services/${id}/sources?` + query); setSources(data.items || []); setSourceNext(data.next_cursor || null); setSourceTotal(data.total_count || 0);
  }, [api]);
  useEffect(() => {if (service?.id && modal === "edit") void loadSources(service.id, sourceCursors.at(-1)).catch(error => setModalError(errorText(error)));}, [service?.id, modal, sourceCursors, loadSources]);
  function resetLabCheck() {
    setLabAvailable(null);
    setLabCheckError("");
  }
  function enterMcpMode() {
    setCreateMode("mcp"); setLabError(""); setLabResults([]); setLabCa(""); setLabCaChoice("bundled");
    resetLabCheck();
  }
  async function checkLab() {
    if (labBusy || labChecking || !labEndpoint.trim() || !labToken.trim() || !labCaReady) return;
    resetLabCheck();
    setLabChecking(true);
    try {
      const ca = labCaChoice === "custom" ? labCa.trim() : "";
      const result = await api("/services/mcp/check", "POST", {
        endpoint: labEndpoint.trim(),
        credential: labToken,
        ...(ca ? {ca_pem: ca} : {}),
      });
      setLabAvailable(result.resources);
      notifyToast((result.resources || []).length ? "success" : "warning", "Conexión MCP verificada", `${(result.resources || []).length} recurso(s) anunciados por el servidor.`);
    } catch (error) { setLabCheckError(errorText(error)); notifyToast("error","No se pudo verificar el MCP",errorText(error)); }
    finally { setLabChecking(false); }
  }
  async function connectLab(event: React.FormEvent) {
    event.preventDefault();
    if (labBusy || labChecking) return;
    if (!labCaReady) { setLabError("Pegá el certificado CA personalizado o elegí la CA del paquete."); return; }
    setLabBusy(true); setLabError(""); setLabResults([]);
    const lines: string[] = [];
    let hadFailure = false;
    const note = (line: string) => { lines.push(line); setLabResults([...lines]); };
    const endpoint = labEndpoint.trim();
    const ca = labCaChoice === "custom" ? labCa.trim() : "";
    try {
      for (const def of labServices) {
        try {
          const labSource = (resource: LabResource) => ({
            kind: "mcp",
            config: {endpoint, resource_uri: resource.value, synthetic: false, mode: "incremental_lab", poll_seconds: 5, ...(ca ? {ca_pem: ca} : {})},
            credential: labToken,
            analysis: {system: def.system, protocol: def.protocol, adapter: "auto", context: "", rules: rulesFor(resource)},
            enabled: false,
          });
          const found = await api("/services?limit=50&q=" + encodeURIComponent(def.name));
          let svc = (found.items || []).find((i: ServiceData) => i.name === def.name && !i.deleted_at);
          if (!svc) {
            const created = await api("/services", "POST", {name: def.name, description: "Servicio del laboratorio (VM)", context: def.context, enabled: true, idempotency_key: crypto.randomUUID(), source: labSource(def.resources[0])});
            svc = created?.id ? created : (await api("/services?limit=50&q=" + encodeURIComponent(def.name))).items?.find((i: ServiceData) => i.name === def.name && !i.deleted_at);
            if (!svc?.id) throw new Error("No se pudo crear el servicio.");
            note(def.name + ": servicio creado.");
          }
          const listed = await api(`/services/${svc.id}/sources?limit=20`);
          const existing: ServiceData[] = listed.items || [];
          for (const resource of def.resources) {
            const {value: uri, label} = resource;
            try {
              let src = existing.find((x: ServiceData) => x.config?.resource_uri === uri && !x.deleted_at);
              if (src) {
                // Sin CA personalizada se conserva la CA ya guardada en la fuente.
                const needsUpdate = src.config?.endpoint !== endpoint || (ca ? src.config?.ca_pem !== ca : false);
                if (needsUpdate) {
                  // Un endpoint o CA distintos exigen desactivar, comprobar y volver a activar.
                  await api(`/sources/${src.id}`, "PUT", {
                    expected_version: src.version,
                    config: {...src.config, endpoint, ...(ca ? {ca_pem: ca} : {})},
                    enabled: false,
                    ...(labToken.trim() ? {credential: labToken} : {}),
                  });
                  src = await api(`/sources/${src.id}`);
                }
              } else {
                const made = await api(`/services/${svc.id}/sources`, "POST", {...labSource(resource), idempotency_key: crypto.randomUUID()});
                src = made?.id ? made : (await api(`/services/${svc.id}/sources?limit=20`)).items?.find((x: ServiceData) => x.config?.resource_uri === uri && !x.deleted_at);
              }
              if (!src?.id) throw new Error("No se pudo crear la fuente.");
              if (!src.enabled) {
                const check = await api(`/sources/${src.id}/check`, "POST", {});
                if (!check.readable) throw new Error("La comprobación de lectura falló; revisá el endpoint, la credencial y que el laboratorio esté encendido.");
                await api(`/sources/${src.id}`, "PUT", {expected_version: src.version, enabled: true});
                note(def.name + " · " + label + ": fuente activa.");
              } else note(def.name + " · " + label + ": ya estaba activa.");
            } catch (error) {
              hadFailure = true;
              note(def.name + " · " + label + ": " + errorText(error));
            }
          }
        } catch (error) {
          hadFailure = true;
          note(def.name + ": " + errorText(error));
        }
      }
      if (!hadFailure) setDirty(false);
      note(hadFailure ? "Conexión finalizada con errores. Revisá el resultado de cada fuente." : "Conexión finalizada.");
      notifyToast(hadFailure ? "warning" : "success", hadFailure ? "Conexión MCP finalizada con errores" : "Laboratorio conectado", hadFailure ? "Revisá el resultado de cada fuente en el formulario." : "Los servicios y fuentes del laboratorio quedaron configurados.");
      setReload(value => value + 1);
    } catch (error) { setLabError(errorText(error)); notifyToast("error","No se pudo conectar el laboratorio",errorText(error)); } finally { setLabBusy(false); }
  }
  async function open(mode: "create" | "edit" | "delete", selected?: ServiceData) {
    trigger.current = document.activeElement as HTMLElement; setModalError(""); setDirty(false); setSourcesDirty(false); setDiscard(false); setSourceKind(null); setSource(initialSource()); setSourceCursors([null]); setCreateMode("folder"); key.current = crypto.randomUUID();
    setLabServiceType("all"); setLabIncludeAudit(false); setLabRuleDrafts({}); setLabEndpoint("https://192.168.122.210/mcp"); setLabToken(""); setLabCa(""); setLabCaChoice("bundled");
    if (selected) {
      try {const detail = await api("/services/" + selected.id); setService(detail); setForm({name: detail.name || "", description: detail.description || "", context: detail.context || "", enabled: detail.enabled, software_product: detail.software_product || "", software_version: detail.software_version || ""}); setModal(mode);} catch (error) {setError(errorText(error));notifyToast("error","No se pudo abrir el servicio",errorText(error));}
    } else {setService(null); setForm({name: "", description: "", context: "", enabled: true, software_product: "", software_version: ""}); setWithSource(true); setModal(mode);}
  }
  async function save(event: React.FormEvent) {
    event.preventDefault(); setSaving(true); setModalError("");
    try {
      await api(service ? `/services/${service.id}` : "/services", service ? "PUT" : "POST", {...form, ...(service?.software_origin === "mcp" ? {software_product: undefined, software_version: undefined} : {}), ...(service ? {expected_version: service.version} : {idempotency_key: key.current, ...(withSource ? {source: {...source, enabled: false}} : {})})});
      setDirty(false); setModal(null); setNotice(service ? "Servicio actualizado. Los análisis anteriores conservan su contexto." : "Servicio creado. Las fuentes nuevas quedan inactivas hasta que las actives."); notifyToast("success", service ? "Servicio actualizado" : "Servicio creado", service ? "Los análisis anteriores conservan su contexto." : "Las fuentes nuevas quedan inactivas hasta que las actives."); setReload(value => value + 1);
    } catch (error) {setModalError(errorText(error)); notifyToast("error", "No se pudo guardar el servicio", errorText(error));} finally {setSaving(false);}
  }
  async function toggle(item: ServiceData) {
    setError(""); setToggling(item.id);
    try {const detail = await api(`/services/${item.id}`); await api(`/services/${item.id}`, "PUT", {expected_version: detail.version, name: detail.name, description: detail.description || "", context: detail.context || "", enabled: !detail.enabled}); const message=item.enabled ? "Servicio desactivado. Las tareas ya enviadas finalizarán y conservarán su costo." : "Servicio reactivado. Se reanudará la cola pendiente desde sus cursores.";setNotice(message);notifyToast(item.enabled ? "warning" : "success", item.enabled ? "Servicio desactivado" : "Servicio reactivado", message); setReload(value => value + 1);} catch (error) {setError(errorText(error));notifyToast("error","No se pudo cambiar el estado del servicio",errorText(error));} finally {setToggling(null);}
  }
  async function remove() {
    if (!service) return; setSaving(true); setModalError("");
    try {await api(`/services/${service.id}`, "DELETE", {expected_version: service.version}); setModal(null); setNotice("Servicio eliminado del catálogo operativo. Su historial se conserva.");notifyToast("success","Servicio eliminado","Su historial y su evidencia se conservan."); setReload(value => value + 1);} catch (error) {setModalError(errorText(error));notifyToast("error","No se pudo eliminar el servicio",errorText(error));} finally {setSaving(false);}
  }
  async function addSource(event: React.FormEvent) {
    event.preventDefault(); if (!service) return; setSaving(true); setModalError("");
    try {await api(`/services/${service.id}/sources`, "POST", {...source, enabled: false, idempotency_key: key.current}); key.current = crypto.randomUUID(); setSourceKind(null); setSource(initialSource()); await loadSources(service.id); setSourceCursors([null]); setReload(value => value + 1);notifyToast("success","Fuente agregada","Queda inactiva hasta que la actives.");} catch (error) {setModalError(errorText(error));notifyToast("error","No se pudo agregar la fuente",errorText(error));} finally {setSaving(false);}
  }
  const openSource = (kind: "folder" | "mcp") => {setSource(kind === "folder" ? initialSource() : {...initialSource(), kind: "mcp", config: {endpoint: "", resource_uri: "", synthetic: true}}); key.current = crypto.randomUUID(); setModalError(""); setSourceKind(kind);};
  const updateForm = (patch: Partial<typeof form>) => {setForm(value => ({...value, ...patch})); setDirty(true);};
  return <section className="service-catalog" aria-labelledby="services-heading">
    <div className="list-heading"><div><h2 id="services-heading">Servicios</h2><p className="muted">Organizá las fuentes, los registros y el contexto de análisis de cada servicio.</p></div><ArcButton onClick={() => void open("create")}>Agregar servicio</ArcButton></div>
    <div className="service-filters"><ArcInput label="Buscar servicios" type="search" value={q} onChange={event => {setQ(event.target.value); resetPage();}} placeholder="Nombre o descripción" /><ArcSelect label="Estado del servicio" value={state || "__all__"} onValueChange={v => {setState(v === "__all__" ? "" : v); resetPage();}} options={[{value:"__all__",label:"Activos e inactivos"},{value:"active",label:"Activos"},{value:"inactive",label:"Inactivos"},{value:"deleted",label:"Eliminados"},{value:"all",label:"Todos, con historial"}]} /><ArcSelect label="Tipo de fuente" value={kind || "__all__"} onValueChange={v => {setKind(v === "__all__" ? "" : v); resetPage();}} options={[{value:"__all__",label:"Todos los tipos"},{value:"folder",label:"Carpeta"},{value:"mcp",label:"MCP"}]} /></div>
    <details className="service-advanced-filters"><summary>Filtros avanzados{[system, protocol, sourceState].filter(Boolean).length > 0 && <span className="filter-badge">{[system, protocol, sourceState].filter(Boolean).length} activos</span>}</summary><div className="service-filters advanced"><ArcInput label="Sistema" value={system} maxLength={80} onChange={event => {setSystem(event.target.value); resetPage();}} placeholder="Nginx" /><ArcInput label="Protocolo" value={protocol} maxLength={80} onChange={event => {setProtocol(event.target.value); resetPage();}} placeholder="HTTP" /><ArcSelect label="Estado de fuente" value={sourceState || "__all__"} onValueChange={v => {setSourceState(v === "__all__" ? "" : v); resetPage();}} options={[{value:"__all__",label:"Todas"},{value:"active",label:"Activa"},{value:"inactive",label:"Inactiva"},{value:"healthy",label:"Al día"},{value:"degraded",label:"Degradada"},{value:"blocked",label:"Bloqueada"},{value:"pending",label:"Sin lecturas"}]} /></div></details>
    {[q, state, kind, system, protocol, sourceState].some(Boolean) && <div className="service-filter-actions"><span role="status">{total} servicios con estos filtros</span><ArcButton type="button" variant="secondary" onClick={() => {setQ(""); setState(""); setKind(""); setSystem(""); setProtocol(""); setSourceState(""); resetPage();}}>Limpiar filtros</ArcButton></div>}
    {unassigned > 0 && <p className="muted">{unassigned} registros históricos pendientes de asociación; no se asignan automáticamente.</p>}
    {unresolvedRules > 0 && <p className="muted">{unresolvedRules} reglas históricas requieren seleccionar un servicio; permanecen inactivas.</p>}
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    <div className="table-scroll" aria-busy={loading}><ArcTable caption="Catálogo de servicios" rows={items} rowKey="id" emptyMessage="Sin servicios" columns={[
      {key: "name", label: "Servicio", render: (_v, item) => <><span>{item.name}</span>{item.description && <small>{item.description}</small>}</>},
      {key: "source_count", label: "Fuentes", render: (_v, item) => <>{item.source_count ?? item.sources_count ?? 0}<small>{(item.source_kinds || []).map((kind: string) => kind === "folder" ? "Carpeta" : "MCP").join(", ") || "Sin fuentes"}</small></>},
      {key: "state", label: "Estado", render: (_v, item) => <><span className="status-pill" data-state={item.deleted_at ? "deleted" : item.enabled ? "active" : "inactive"}>{serviceState(item)}</span><small>{sourceHealth(item.status || item.health)}</small>{Number(item.cve_affecting) > 0 && <span className="cve-badge">{item.cve_affecting} CVE te afectan</span>}{item.cve_checked_at && <small>Último chequeo CVE: {dateText(item.cve_checked_at)}{Number(item.cve_affecting) > 0 ? "" : " · sin impacto"}</small>}</>},
      {key: "last_received_at", label: "Última lectura", render: (_v, item) => dateText(item.last_received_at || item.last_ingested_at)},
      {key: "actions", label: "Acciones", render: (_v, item) => <div className="service-row-actions service-actions-compact"><ArcButton variant="secondary" size="sm" onClick={() => void open("edit", item)}>{item.deleted_at ? "Ver servicio" : "Editar"}</ArcButton>{!item.deleted_at && <><ToggleSwitch label={item.enabled ? `Desactivar ${item.name}` : `Reactivar ${item.name}`} checked={!!item.enabled} disabled={toggling === item.id} onChange={() => void toggle(item)} /><ActionMenu label="Acciones" items={[{label: "Eliminar", onSelect: () => void open("delete", item)}]} /></>}</div>},
    ]} /></div>
    {loading && <p role="status">Cargando servicios…</p>}{!loading && !items.length && <p>{q || state || kind || system || protocol || sourceState ? "No hay servicios que coincidan con estos filtros." : "Agregá un servicio para asociar sus fuentes de logs y su contexto de análisis."}</p>}
    <nav className="pagination" aria-label="Páginas de servicios"><ArcSelect label="Servicios por página" value={String(size)} onValueChange={v => {setSize(Number(v)); resetPage();}} options={[10, 25, 50].map(value => ({value: String(value), label: String(value)}))} /><span>{total} servicios · Página {cursors.length}</span><ArcButton variant="secondary" disabled={loading || cursors.length === 1} onClick={() => setCursors(previous => previous.slice(0, -1))}>Anterior</ArcButton><ArcButton variant="secondary" disabled={loading || !next} onClick={() => next && setCursors(previous => [...previous, next])}>Siguiente</ArcButton></nav>
    <ArcDialog open={!!modal} onOpenChange={open => {if (!open && !labBusy && !labChecking) close();}}>
    <ArcDialogContent title={modal === "create" ? "Agregar servicio" : modal === "delete" ? "Eliminar servicio" : service?.deleted_at ? "Historial del servicio" : "Editar servicio"} className="service-dialog" onOpenAutoFocus={event => {event.preventDefault(); (event.currentTarget as HTMLElement).querySelector<HTMLElement>("[data-initial-focus]")?.focus();}} onCloseAutoFocus={event => {event.preventDefault(); trigger.current?.focus();}}>
      {modalError && <p role="alert">{modalError}</p>}
      {discard && <div ref={confirmation} tabIndex={-1} className="service-confirm" role="alert"><p>Hay cambios sin guardar. ¿Querés descartarlos?</p><ArcButton type="button" onClick={() => {setDirty(false); setSourcesDirty(false); setDiscard(false); setModal(null);}}>Descartar cambios</ArcButton><ArcButton type="button" variant="secondary" onClick={() => setDiscard(false)}>Seguir editando</ArcButton></div>}
      {modal === "create" && <fieldset className="create-mode" disabled={labBusy || labChecking}><legend className="visually-hidden">Origen de los registros</legend><SegmentedControl label="Tipo de fuente del servicio" fullWidth value={createMode} onValueChange={value => {if (value === "mcp") void enterMcpMode(); else setCreateMode("folder");}} options={[{value: "folder", label: "Carpeta de logs"}, {value: "mcp", label: "MCP"}]} /></fieldset>}
      {modal === "create" && createMode === "mcp" ? <div className="lab-connect">
      <form onSubmit={connectLab}>
        <fieldset disabled={labBusy || labChecking}>
        <legend className="visually-hidden">Conexión y reglas del servicio MCP</legend>
        <ArcSelect label="Tipo de servicio normalizado" value={labServiceType} disabled={labBusy || labChecking} onValueChange={value => {setLabServiceType(value); setLabResults([]); setLabError("");}} options={[{value: "all", label: "Todos los servicios del laboratorio"}, ...LAB_SERVICES]} />
        <ArcInput label="Endpoint MCP" required value={labEndpoint} onChange={event => {setLabEndpoint(event.target.value); resetLabCheck();}} placeholder="https://192.168.122.210/mcp" />
        <ArcInput label="Credencial MCP" type="password" required value={labToken} onChange={event => {setLabToken(event.target.value); resetLabCheck();}} autoComplete="new-password" />
        <ArcSelect label="Certificado CA" value={labCaChoice} disabled={labBusy || labChecking} onValueChange={value => {setLabCaChoice(value as "bundled" | "custom"); resetLabCheck();}} options={[{value: "bundled", label: "Usar la CA del paquete (lab/lab-ca.pem)"}, {value: "custom", label: "Aportar una CA personalizada"}]} />
        {labCaChoice === "custom" && <ArcTextarea label="Certificado CA (PEM)" value={labCa} onChange={event => {setLabCa(event.target.value); resetLabCheck();}} placeholder="Pegá el contenido de ca.pem (-----BEGIN CERTIFICATE-----...)" />}
        <section className="lab-source-rules" aria-labelledby="lab-rules-heading">
          <h3 id="lab-rules-heading">Reglas de detección por fuente</h3>
          <p className="muted">Abrí una fuente para agregar o ajustar las reglas que se guardarán al crearla. Para fuentes existentes, usá Editar servicio → Fuentes → Reglas.</p>
          {labServices.some(def => def.value === "mysql") && <>
            <label><input type="checkbox" checked={labIncludeAudit} onChange={event => setLabIncludeAudit(event.target.checked)} /> Incluir auditoría de MySQL</label>
            {labIncludeAudit && <p className="muted">Requiere el archivo de auditoría en la VM. Esta fuente conserva el texto y actualmente no genera eventos para las reglas.</p>}
          </>}
          {labResources.map(resource => {
            const rules = rulesFor(resource);
            return <details key={resource.value}>
              <summary>{resource.label} ({rules.length} {rules.length === 1 ? "regla" : "reglas"})</summary>
              <RulePicker rules={rules} onRules={next => {
                if (!labBusy) {
                  setLabRuleDrafts(drafts => ({...drafts, [resource.value]: next}));
                  setDirty(true);
                }
              }} sourceKind="mcp" />
            </details>;
          })}
        </section>
        </fieldset>
        {labCheckError && <p role="alert">{labCheckError}</p>}
        {labAvailable && <p role="status">{labMissing.length
          ? `El MCP respondió. Recursos seleccionados que no anuncia: ${labMissing.map(resource => resource.label).join(", ")}.`
          : "Conexión correcta. El MCP anuncia todos los recursos seleccionados."}</p>}
        {labError && <p role="alert">{labError}</p>}
        {labResults.length > 0 && <ul className="lab-connect-results" aria-live="polite">{labResults.map((line, i) => <li key={i}>{line}</li>)}</ul>}
        <p className="muted">Sentinel comprueba la lectura antes de activar cada fuente. La versión del software llega desde el MCP.</p>
        <div className="service-row-actions">
          <ArcButton type="button" variant="secondary" disabled={labBusy || labChecking || !labEndpoint.trim() || !labToken.trim() || !labCaReady} onClick={() => void checkLab()}>{labChecking ? "Probando conexión…" : "Probar conexión"}</ArcButton>
          <ArcButton type="submit" disabled={labBusy || labChecking || !labCaReady}>{labBusy ? "Conectando…" : labServiceType === "all" ? "Conectar laboratorio" : "Conectar servicio"}</ArcButton>
          {labResults.length > 0 && !labBusy && <ArcButton type="button" onClick={() => {setDirty(false); setSourcesDirty(false); setDiscard(false); setModal(null);}}>Cerrar</ArcButton>}
          <ArcButton type="button" variant="secondary" disabled={labBusy || labChecking} onClick={close}>Cancelar</ArcButton>
        </div>
      </form>
      </div> : modal === "delete" ? <div className="service-delete"><p>Vas a eliminar <strong>{service?.name}</strong> del catálogo operativo y retirar sus fuentes. Se conservarán logs, incidencias, conversaciones y costos.</p><p>Las tareas aún no enviadas se detendrán. Las solicitudes ya enviadas terminarán y se contabilizarán.</p><div className="service-row-actions"><ArcButton type="button" data-initial-focus disabled={saving} onClick={() => void remove()}>{saving ? "Eliminando…" : "Confirmar eliminación"}</ArcButton><ArcButton type="button" variant="secondary" disabled={saving} onClick={close}>Cancelar</ArcButton></div></div> : <>
        <form onSubmit={save} className="service-identity-form"><fieldset disabled={saving || !!service?.deleted_at}><legend className="visually-hidden">Identidad y contexto del servicio</legend><ArcInput label="Nombre del servicio" data-initial-focus required maxLength={128} value={form.name} onChange={event => updateForm({name: event.target.value})} /><ArcTextarea label="Descripción" maxLength={2000} rows={2} value={form.description} onChange={event => updateForm({description: event.target.value})} /><ArcTextarea label="Contexto para el análisis" maxLength={4000} rows={5} value={form.context} onChange={event => updateForm({context: event.target.value})} aria-describedby="service-context-help" /><p id="service-context-help" className="muted">Explicá qué hace este servicio y qué actividad es esperada. Este contexto orienta el análisis; no cambia permisos ni ejecuta acciones.</p><div className="switch-row"><span>Servicio activo</span><ToggleSwitch label="Servicio activo" checked={form.enabled} onChange={next => updateForm({enabled: next})} /></div>
        <fieldset className="software-fields"><legend>Software monitoreado (detector de CVE)</legend><ArcSelect label="Producto conocido" value={SOFTWARE_PRESETS.some(p => p.value === form.software_product) ? form.software_product : form.software_product ? "__custom" : "__none__"} onValueChange={value => {if (value === "__none__") updateForm({software_product: "", software_version: ""}); else if (value === "__custom") updateForm({software_product: ""}); else updateForm({software_product: value});}} options={[{value:"__none__",label:"Sin software declarado"}, ...SOFTWARE_PRESETS.map(p => ({value: p.value, label: p.label})), {value:"__custom",label:"Otro (escribir el CPE)"}]} /><ArcInput label="Producto CPE (proveedor:producto)" maxLength={120} placeholder="apache:http_server" value={form.software_product} onChange={event => {const value = event.target.value; updateForm(value ? {software_product: value} : {software_product: "", software_version: ""});}} /><div className={form.software_product ? undefined : "field-disabled"}><ArcInput label="Versión instalada" maxLength={64} placeholder="2.4.58" disabled={!form.software_product} value={form.software_version} onChange={event => updateForm({software_version: event.target.value})} />{!form.software_product && <small>Elegí o escribí primero el producto.</small>}</div><p className="muted">Con software y versión declarados, el detector compara tu versión con los CVE publicados en NVD. Con carpeta de logs, escribí la versión. Con MCP de laboratorio, Sentinel recibe la versión del estado publicado por el servicio y la actualiza al leerlo.</p></fieldset>
        {modal === "create" && <fieldset className="service-initial-source"><legend>Fuente inicial</legend><div className="switch-row"><span>Agregar una fuente ahora</span><ToggleSwitch label="Agregar una fuente ahora" checked={withSource} onChange={next => {setWithSource(next); setDirty(true);}} /></div>{withSource && <SourceFields source={source} change={value => {setSource(value); setDirty(true);}} lockKind />}</fieldset>}
        <div className="service-dialog-actions"><ArcButton type="button" variant="secondary" disabled={saving} onClick={close}>Cancelar</ArcButton>{!service?.deleted_at && <ArcButton disabled={saving}>{saving ? "Guardando…" : modal === "create" ? "Guardar servicio" : "Guardar cambios"}</ArcButton>}</div></fieldset></form>
        {modal === "edit" && service && <section className="service-sources" aria-labelledby="service-sources-heading"><div className="list-heading"><h3 id="service-sources-heading">Fuentes del servicio</h3>{!service.deleted_at && <ActionMenu label="Agregar fuente" text="Agregar fuente" items={[{label: "Carpeta de logs", onSelect: () => openSource("folder")}, {label: "MCP de lectura", onSelect: () => openSource("mcp")}]} />}</div><p className="muted">Cada fuente pertenece a este servicio. Las fuentes nuevas se guardan inactivas; activalas cuando su configuración esté lista.</p><ul>{sources.map(item => <SourceRow key={item.id + ":" + item.version} api={api} serviceId={service.id} source={item} onDirty={() => setSourcesDirty(true)} onCancelEdit={() => setSourcesDirty(false)} onSaved={() => {setSourcesDirty(false); void loadSources(service.id, sourceCursors.at(-1)).catch(error => setModalError(errorText(error))); setReload(value => value + 1);}} />)}</ul>{!sources.length && <p>Este servicio todavía no tiene fuentes.</p>}
          <nav className="service-picker-pages" aria-label="Páginas de fuentes"><ArcButton type="button" variant="secondary" disabled={sourceCursors.length === 1} onClick={() => setSourceCursors(previous => previous.slice(0, -1))}>Fuentes anteriores</ArcButton><span>{sourceTotal} fuentes · Página {sourceCursors.length}</span><ArcButton type="button" variant="secondary" disabled={!sourceNext} onClick={() => sourceNext && setSourceCursors(previous => [...previous, sourceNext])}>Más fuentes</ArcButton></nav>

        </section>}
        {modal === "edit" && service && <CvePanel api={api} service={service} />}
        {modal === "edit" && service && <StructurePanel api={api} service={service} />}
        {modal === "edit" && service && <ObservabilityPanel api={api} service={service} sources={sources} />}
      </>}
    </ArcDialogContent>
    </ArcDialog>
    {sourceKind && <ArcDialog open onOpenChange={open => {if (!open && !saving) setSourceKind(null);}}>
    <ArcDialogContent title={sourceKind === "mcp" ? "Agregar fuente · MCP de lectura" : "Agregar fuente · Carpeta de logs"} className="service-dialog source-dialog" onOpenAutoFocus={event => {event.preventDefault(); (event.currentTarget as HTMLElement).querySelector<HTMLElement>("[data-initial-focus]")?.focus();}}>
      {modalError && <p role="alert">{modalError}</p>}
      <form onSubmit={addSource}><fieldset disabled={saving}><legend className="visually-hidden">Nueva fuente para {service?.name}</legend><SourceFields source={source} change={setSource} /><p className="muted">La fuente se guarda inactiva; activala desde la lista cuando su configuración esté lista.</p><div className="service-dialog-actions"><ArcButton type="button" variant="secondary" disabled={saving} onClick={() => setSourceKind(null)}>Cancelar nueva fuente</ArcButton><ArcButton disabled={saving}>{saving ? "Guardando fuente…" : "Guardar nueva fuente"}</ArcButton></div></fieldset></form>
    </ArcDialogContent>
    </ArcDialog>}
  </section>;
}
