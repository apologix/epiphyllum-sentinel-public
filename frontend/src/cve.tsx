import React, { useCallback, useEffect, useRef, useState } from "react";
import { Button as ArcButton } from "@/components/arc/button/button";
import { Select as ArcSelect } from "@/components/arc/select/select";
import { Input as ArcInput } from "@/components/arc/input/input";
import { Textarea as ArcTextarea } from "@/components/arc/textarea/textarea";
import { Dialog as ArcDialog, DialogContent as ArcDialogContent } from "@/components/arc/dialog/dialog";
import { SortableDataTable as ArcTable } from "@/components/arc/sortable-data-table/sortable-data-table";
import { ServicePicker, type ServiceData } from "./services";
import { DonutChart } from "@/components/arc/donut-chart/donut-chart";
import { EmptyState } from "@/components/arc/empty-state/empty-state";
import { notifyToast } from "./toast";

type Api = (path: string, method?: string, body?: unknown) => Promise<ServiceData>;
const errorText = (error: unknown) => error instanceof Error ? error.message : "No se pudo completar la operación.";
const dateText = (value?: string) => value ? new Date(value).toLocaleString("es-CR", {timeZone: "America/Costa_Rica"}) : "Sin fecha";
const failReason = (reason?: string) => ({provider_unavailable: "El proveedor no respondió; probá de nuevo más tarde.", invalid_model_response: "La respuesta del modelo no tuvo el formato esperado."} as Record<string, string>)[reason || ""] || reason || "La explicación no pudo generarse.";

export function CveTab({api, refresh = 0, pollMs = 2500}: {api: Api; refresh?: number; pollMs?: number}) {
  const [services, setServices] = useState<ServiceData[]>([]), [dailyEnabled, setDailyEnabled] = useState(false);
  const [items, setItems] = useState<ServiceData[]>([]), [total, setTotal] = useState(0), [loading, setLoading] = useState(true);
  const [error, setError] = useState(""), [notice, setNotice] = useState(""), [busyAll, setBusyAll] = useState(false), [checkingId, setCheckingId] = useState("");
  const [serviceFilter, setServiceFilter] = useState(""), [severity, setSeverity] = useState(""), [affects, setAffects] = useState(""), [query, setQuery] = useState("");
  const [page, setPage] = useState(0), [pageSize, setPageSize] = useState(10);
  // Solo la primera carga muestra el estado de carga: los refrescos por SSE
  // no deben re-renderizar la tabla ni hacer saltar la página.
  const loaded = useRef(false);
  const [suggestions, setSuggestions] = useState<Record<string, ServiceData>>({});
  const [explain, setExplain] = useState<ServiceData | null>(null), [question, setQuestion] = useState("¿Cómo me afecta esta vulnerabilidad y cómo la puedo solucionar?"), [explanations, setExplanations] = useState<ServiceData[]>([]), [asking, setAsking] = useState(false), [explainError, setExplainError] = useState("");
  const [track, setTrack] = useState(0), [trackError, setTrackError] = useState("");
  const explainRef = useRef<ServiceData | null>(null);
  explainRef.current = explain;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const [donutFindings, setDonutFindings] = useState<ServiceData[]>([]);
  useEffect(() => { void api("/cve/findings?limit=100&offset=0&affects=true").then((d: ServiceData) => setDonutFindings(d.items || [])).catch(() => {}); }, [api, refresh, total]);
  // UI-ARC-07 (punto 3): el donut también necesita TODOS los hallazgos de
  // la última comprobación para su cascada (ver donutScenario más abajo).
  const [allFindings, setAllFindings] = useState<ServiceData[]>([]);
  useEffect(() => { void api("/cve/findings?limit=100&offset=0").then((d: ServiceData) => setAllFindings(d.items || [])).catch(() => {}); }, [api, refresh, total]);

  const loadSummary = useCallback(async () => {
    const data = await api("/cve/services");
    setServices(data.items || []); setDailyEnabled(!!data.daily_enabled);
  }, [api]);
  const loadFindings = useCallback(async () => {
    if (!loaded.current) setLoading(true);
    const params = new URLSearchParams({limit: String(pageSize), offset: String(page * pageSize)});
    if (serviceFilter) params.set("service_id", serviceFilter);
    if (severity) params.set("severity", severity);
    if (affects) params.set("affects", affects);
    if (query.trim()) params.set("q", query.trim());
    try {const data = await api("/cve/findings?" + params); setItems(data.items || []); setTotal(data.total_count || 0); setError("");}
    catch (err) {setError(errorText(err));}
    finally {loaded.current = true; setLoading(false);}
  }, [api, page, pageSize, serviceFilter, severity, affects, query]);
  useEffect(() => {void loadSummary().catch(err => setError(errorText(err)));}, [loadSummary, refresh]);
  useEffect(() => {void loadFindings();}, [loadFindings, refresh]);
  useEffect(() => {setPage(0);}, [serviceFilter, severity, affects, query, pageSize]);
  useEffect(() => {
    const missing = services.filter(s => !s.software_product);
    for (const s of missing) {
      if (suggestions[s.id]) continue;
      void api(`/services/${s.id}/cve/banner-suggestions`).then(data => setSuggestions(prev => ({...prev, [s.id]: data}))).catch(() => {});
    }
  }, [api, services]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(""), 6000);
    return () => clearTimeout(timer);
  }, [notice]);

  const loadExplanations = useCallback(async (findingId: string) => {
    const data = await api(`/cve-findings/${findingId}/explanations`);
    return (data.items || []) as ServiceData[];
  }, [api]);
  // El seguimiento se reinicia al abrir otro CVE, después de preguntar y al
  // reintentar una consulta de estado. Una respuesta tardía de otro hallazgo
  // no puede escribir en el cuadro actual.
  useEffect(() => {
    if (!explain) return;
    const findingId = explain.id;
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    const tick = async () => {
      try {
        const rows = await loadExplanations(findingId);
        if (cancelled) return;
        setExplanations(rows);
        setTrackError("");
        if (!rows.some((r: ServiceData) => r.state === "pending" || r.state === "generating")) {
          if (timer) clearInterval(timer);
        }
      } catch (err) {
        if (!cancelled) {
          setTrackError(errorText(err));
          notifyToast("warning", "No se pudo consultar el estado de la explicación", errorText(err));
        }
      }
    };
    void tick();
    timer = setInterval(() => { void tick(); }, pollMs);
    return () => { cancelled = true; if (timer) clearInterval(timer); };
  }, [explain, track, loadExplanations, pollMs]);

  async function runAll() {
    setBusyAll(true); setError(""); setNotice("");
    try {
      const data = await api("/cve/checks/run-all", "POST", {});
      const okCount = (data.results || []).filter((r: ServiceData) => r.state === "completed").length;
      setNotice(`Comprobación terminada: ${okCount} de ${(data.results || []).length} servicios consultados en NVD.`);
      notifyToast(okCount ? "success" : "warning", "Comprobación CVE terminada", `${okCount} de ${(data.results || []).length} servicios consultados en NVD.`);
      await loadSummary(); await loadFindings();
    } catch (err) {setError(errorText(err)); notifyToast("error", "La comprobación CVE falló", errorText(err));}
    finally {setBusyAll(false);}
  }
  async function runOne(service: ServiceData) {
    setCheckingId(service.id); setError("");
    try {await api(`/services/${service.id}/cve-checks`, "POST", {}); setNotice(`Comprobación terminada: ${service.name} consultado en NVD.`); notifyToast("success", "Comprobación CVE terminada", `${service.name} consultado en NVD.`); await loadSummary(); await loadFindings();}
    catch (err) {setError(errorText(err)); notifyToast("error", "La comprobación CVE falló", errorText(err));}
    finally {setCheckingId("");}
  }
  async function ask() {
    const target = explain;
    if (!target) return;
    setAsking(true); setExplainError("");
    try {
      await api(`/cve-findings/${target.id}/explanations`, "POST", {question});
      const rows = await loadExplanations(target.id);
      if (explainRef.current?.id !== target.id) return;
      setExplanations(rows);
      // El seguimiento inicial pudo haber terminado sin pendientes: este
      // contador lo reanuda sin crear otra solicitud de IA.
      setTrack(t => t + 1);
    } catch (err) {if (explainRef.current?.id === target.id) {setExplainError(errorText(err));notifyToast("error","No se pudo enviar la pregunta al CVE",errorText(err));}}
    finally {if (explainRef.current?.id === target.id) setAsking(false);}
  }
  function openFinding(finding: ServiceData) {
    setExplain(finding);
    setExplanations([]);
    setExplainError("");
    setTrackError("");
    setAsking(false);
    setTrack(0);
  }
  function closeFinding() {
    setExplain(null);
    setExplanations([]);
    setExplainError("");
    setTrackError("");
    setAsking(false);
  }
  function retryTracking() {
    setTrackError("");
    setTrack(t => t + 1);
  }
  const declared = services.filter(s => s.software_product);
  const SEV_COLORS: Record<string, string> = { critical: "#e5484d", high: "#f76b15", medium: "#ffb224", low: "#46a758", unknown: "#8b9bab" };
  const SEV_LABELS: Record<string, string> = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", unknown: "Sin puntaje" };
  const sevDataOf = (list: ServiceData[]) => ["critical", "high", "medium", "low", "unknown"].map(k => ({ key: k, label: SEV_LABELS[k], value: list.filter(f => (f.severity || "unknown") === k).length, color: SEV_COLORS[k] })).filter(d => d.value > 0);
  const donutData = sevDataOf(donutFindings);
  const allSevData = sevDataOf(allFindings);
  const affectingTotal = services.reduce((a, s) => a + (s.check?.state === "completed" ? Number(s.check.affecting_count || 0) : 0), 0);
  const checkedCount = services.filter(s => s.check?.state === "completed").length;
  // UI-ARC-07 (punto 3): el donut está SIEMPRE presente con datos del
  // sistema, en cascada: (1) hallazgos que afectan por severidad;
  // (2) todos los hallazgos de la última comprobación por severidad;
  // (3) sin hallazgos todavía: cobertura de comprobación (comprobados
  // vs pendientes), con el centro en formato «N de M». Antes dependía
  // solo de (1) y con 0 que afectan la tarjeta era un EmptyState vacío.
  const donutScenario = donutData.length ? 1 : allSevData.length ? 2 : services.length ? 3 : 0;
  const coverageData = [{key: "checked", label: "Comprobados", value: checkedCount, color: "#46a758"}, {key: "pending", label: "Pendientes de comprobar", value: services.length - checkedCount, color: "#5b6b7d"}].filter(d => d.value > 0);
  const donutTitle = donutScenario === 1 ? "Hallazgos que te afectan, por severidad" : donutScenario === 2 ? "Hallazgos de la última comprobación, por severidad" : "Cobertura de comprobación";
  const coverageFormat = (value: number) => value === services.length && services.length > 0 ? `${checkedCount} de ${services.length}` : String(value);
  return <section aria-labelledby="cve-tab-heading" className="cve-tab">
    {/* UI-ARC-07 (punto 2b): la nota del worker vive como línea secundaria
        bajo el título de la sección, no como bloque suelto bajo la grilla. */}
    <div className="list-heading"><div><h2 id="cve-tab-heading">Vulnerabilidades (CVE)</h2><p className="muted cve-worker-note">Worker pasivo: {dailyEnabled ? <strong>activado (automático)</strong> : <strong>desactivado en Ajustes</strong>} — comprueba solo, una vez al día, los servicios cuyo último chequeo supera las 24 h y que tienen una versión confirmada: declarada por el operador o publicada por el propio servicio vía MCP (version.json). Los banners de la evidencia son solo sugerencias para el operador: nunca se aplican automáticamente. Sin versión confirmada no se consulta NVD. Sentinel no corre ninguna herramienta ni escanea: consulta NVD por la versión confirmada, y la IA solo explica con ese contexto. Podés desactivar el chequeo diario en Ajustes → Detector de CVE.</p></div><ArcButton disabled={busyAll || !declared.length} onClick={() => void runAll()}>{busyAll ? "Consultando NVD…" : "Comprobar todo ahora"}</ArcButton></div>
    {/* UI-ARC-05 (punto 14): jerarquía nueva — 1) resumen con KPIs y donut,
        2) servicios y su software, 3) hallazgos con filtros en grilla. */}
    <div className="cve-summary-grid">
      <div className="cve-kpis">
        <div><span>Servicios monitoreados</span><strong>{declared.length} de {services.length}</strong></div>
        <div><span>CVE que te afectan</span><strong>{affectingTotal}</strong></div>
        <div><span>Servicios comprobados</span><strong>{checkedCount} de {services.length}</strong></div>
        <div><span>Chequeo diario</span><strong>{dailyEnabled ? "Activado" : "Desactivado"}</strong></div>
      </div>
      <div className="cve-donut" aria-label={donutTitle}>
        <h3>{donutTitle}</h3>
        {donutScenario === 1 && <DonutChart label="Distribución por severidad de los CVE que te afectan" data={donutData} totalLabel="Te afectan" size={176} />}
        {donutScenario === 2 && <><DonutChart label="Distribución por severidad de los hallazgos de la última comprobación" data={allSevData} totalLabel="Hallazgos" size={176} /><p className="muted">Ninguno de estos hallazgos afecta a tus versiones declaradas.</p></>}
        {donutScenario === 3 && <><DonutChart label="Cobertura de comprobación de servicios" data={coverageData} totalLabel="Servicios" size={176} formatValue={coverageFormat} /><p className="muted">Todavía no hay hallazgos: el gráfico muestra qué servicios ya fueron comprobados contra NVD.</p></>}
        {donutScenario === 0 && <EmptyState title="Sin servicios para comprobar" description="Cuando el catálogo tenga servicios, la distribución por severidad o la cobertura de comprobación aparece acá." />}
      </div>
    </div>
    {error && <p role="alert">{error}</p>}
    {notice && <div className="toast" role="status"><span>{notice}</span><ArcButton type="button" variant="secondary" size="sm" onClick={() => setNotice("")}>Cerrar</ArcButton></div>}
    <h3>Servicios y su software</h3>
    <div className="table-scroll"><ArcTable caption="Servicios y última comprobación CVE" rows={services} rowKey="id" emptyMessage="Sin servicios" columns={[
      {key: "name", label: "Servicio"},
      {key: "software_product", label: "Software", render: (_v, s) => s.software_product ? <>{s.software_product} <strong>{s.software_version}</strong> <span className="status-pill" data-state={["banner", "mcp"].includes(s.software_origin) ? "active" : "inactive"}>{s.software_origin === "mcp" ? "vía MCP" : s.software_origin === "banner" ? "vía banner" : "declarado"}</span></> : <><span className="muted">Sin versión</span>{(suggestions[s.id]?.suggestions || []).map((g: ServiceData) => <span key={g.product + g.version} className="banner-suggestion">Detectado en banners: <strong>{g.product} {g.version}</strong> ({g.records} registros) — sugerencia: no se aplica automáticamente; si es correcta, declarala en Editar servicio o publicala desde el servicio vía MCP.</span>)}</>},
      {key: "check", label: "Último chequeo", render: (_v, s) => s.check ? <>{dateText(s.check.checked_at)}<small>para {s.check.product} {s.check.version}</small>{s.check.state === "failed" && <small>Falló la consulta a NVD: {s.check.error || "fuente no disponible"} (no es lo mismo que cero hallazgos)</small>}</> : s.previous_check ? <><span className="status-pill" data-state="inactive">Pendiente de comprobar</span><small>El último chequeo fue para {s.previous_check.product} {s.previous_check.version} · {dateText(s.previous_check.checked_at)}; la versión actual todavía no se consultó.</small></> : "Nunca"},
      {key: "total_reported", label: "Revisados", render: (_v, s) => s.check?.state === "completed" ? s.check.total_reported : "—"},
      {key: "affecting_count", label: "Te afectan", render: (_v, s) => s.check?.state === "completed" ? <strong>{s.check.affecting_count}</strong> : "—"},
      {key: "action", label: "Acción", render: (_v, s) => s.software_product ? <ArcButton type="button" variant="secondary" size="sm" disabled={checkingId === s.id} onClick={() => void runOne(s)}>{checkingId === s.id ? "Consultando…" : "Comprobar"}</ArcButton> : null},
    ]} /></div>
    {!services.length && <p>Todavía no hay servicios en el catálogo.</p>}
    <h3>Hallazgos de la última comprobación</h3>
    <div className="builds-toolbar cve-filters">
      <ServicePicker api={api} value={serviceFilter} onChange={setServiceFilter} />
      <ArcSelect label="Severidad" value={severity || "__all__"} onValueChange={v => setSeverity(v === "__all__" ? "" : v)} options={[{value:"__all__",label:"Todas"},{value:"critical",label:"Crítica"},{value:"high",label:"Alta"},{value:"medium",label:"Media"},{value:"low",label:"Baja"},{value:"unknown",label:"Sin puntaje"}]} />
      <ArcSelect label="Afectación" value={affects || "__all__"} onValueChange={v => setAffects(v === "__all__" ? "" : v)} options={[{value:"__all__",label:"Todos"},{value:"true",label:"Solo los que me afectan"},{value:"false",label:"Solo los que no me afectan"}]} />
      <ArcInput className="cve-search-input" label="Buscar" type="search" placeholder="CVE o texto…" value={query} onChange={event => setQuery(event.target.value)} />
      <ArcSelect label="Por página" value={String(pageSize)} onValueChange={v => setPageSize(Number(v))} options={[{value:"10",label:"10"},{value:"25",label:"25"},{value:"50",label:"50"}]} />
      <div className="cve-filter-action"><ArcButton type="button" variant="secondary" onClick={() => {setServiceFilter(""); setSeverity(""); setAffects(""); setQuery("");}}>Limpiar filtros</ArcButton></div>
    </div>
    {/* UI-ARC-07 (punto 2d): sin hallazgos NO se renderiza la tabla vacía
        (antes coexistían la fila «Sin hallazgos» de la tabla y un
        EmptyState debajo, una franja enorme duplicada): solo el
        EmptyState compacto. */}
    {(loading || items.length > 0) && <div className="table-scroll" aria-busy={loading}><ArcTable caption="Hallazgos CVE de la última comprobación de cada servicio" rows={[...items, ...(items.length > 0 ? Array.from({length: Math.max(0, pageSize - items.length)}, (_, i) => ({id: "filler-" + i, __filler: true} as ServiceData)) : [])]} rowKey="id" emptyMessage="Sin hallazgos" columns={[
      {key: "severity", label: "Severidad", render: (_v, f) => f.__filler ? "" : <span className={`severity-pill severity-${f.severity}`}>{f.severity}{f.base_score != null ? ` ${Number(f.base_score).toFixed(1)}` : ""}</span>},
      {key: "cve_id", label: "CVE", render: (_v, f) => f.__filler ? "" : <><a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer">{f.cve_id}</a>{f.fixed_version && f.affects && <small>Corregido en {f.fixed_version}</small>}</>},
      {key: "service_name", label: "Servicio", render: (_v, f) => f.__filler ? "" : f.service_name},
      {key: "product", label: "Software", render: (_v, f) => f.__filler ? "" : `${f.product} ${f.version}`},
      {key: "affects", label: "Afectación", render: (_v, f) => f.__filler ? "" : f.affects ? <span className="cve-affects">Te afecta</span> : <span className="muted">No te afecta</span>},
      {key: "published", label: "Publicado", render: (_v, f) => f.__filler ? "" : dateText(f.published)},
      {key: "action", label: "Acción", render: (_v, f) => f.__filler ? "" : <ArcButton type="button" variant="secondary" size="sm" onClick={() => openFinding(f)}>Preguntar a la IA</ArcButton>},
    ]} /></div>}
    {!loading && !items.length && <EmptyState className="cve-empty-state" title="No hay hallazgos con esos filtros" description="Comprobá un servicio para generar su primera lista, o limpiá los filtros para ver más." />}
    <nav className="pagination" aria-label="Páginas de hallazgos CVE"><ArcButton variant="secondary" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Anterior</ArcButton><span>{total} hallazgos · Página {page + 1} de {pages}</span><ArcButton variant="secondary" disabled={(page + 1) * pageSize >= total} onClick={() => setPage(p => p + 1)}>Siguiente</ArcButton></nav>
    {explain && <ArcDialog open onOpenChange={open => {if (!open) closeFinding();}}>
    <ArcDialogContent title={`${explain.cve_id} · ${explain.service_name}`} className="service-dialog cve-dialog">
      <p><span className={`severity-pill severity-${explain.severity}`}>{explain.severity}{explain.base_score != null ? ` ${Number(explain.base_score).toFixed(1)}` : ""}</span> {explain.affects ? <span className="cve-affects">Te afecta</span> : <span className="muted">No te afecta</span>} · {explain.product} {explain.version}{explain.fixed_version ? ` · Corregido en ${explain.fixed_version}` : ""}</p>
      {explain.summary && <p>{explain.summary}</p>}
      {explain.affected_range && <p className="muted">Versiones afectadas según NVD: {explain.affected_range}.</p>}
      <div className="cve-question">
        <ArcTextarea label="Tu pregunta" rows={3} maxLength={1000} value={question} onChange={event => setQuestion(event.target.value)} />
        <div className="cve-question-action"><ArcButton type="button" loading={asking} disabled={asking || !question.trim()} onClick={() => void ask()}>Preguntar a la IA</ArcButton></div>
      </div>
      {explainError && <p role="alert">{explainError}</p>}
      {trackError && <p role="alert" className="cve-track-error">No se pudo consultar el estado de la explicación: {trackError}. <ArcButton type="button" variant="secondary" size="sm" onClick={retryTracking}>Volver a consultar</ArcButton></p>}
      <p className="muted">La IA responde solo con el contexto que el backend le entrega (el hallazgo de NVD, tu versión y el contexto del servicio); no navega ni ejecuta nada. Con el perfil mock la respuesta es la generación local sin gasto y va etiquetada. En live se envía al proveedor habilitado; si el tope de gasto de la sesión está activo, se respeta, y sin clave o proveedor configurado no se envía nada.</p>
      <ul className="explanations" aria-live="polite" aria-busy={explanations.some(e => e.state === "pending" || e.state === "generating")}>
        {explanations.map(e => <li key={e.id} className="explanation">
          <p><strong>{e.question}</strong></p>
          {(e.state === "pending" || e.state === "generating") && <p role="status" className="generating"><span className="spinner" aria-hidden="true" /> Generando la explicación…</p>}
          {e.state === "ready" && <><p className="explanation-answer">{e.answer}</p>{Array.isArray(e.human_checks) && e.human_checks.length > 0 && <><p><strong>Verificaciones humanas:</strong></p><ul>{e.human_checks.map((c: string) => <li key={c}>{c}</li>)}</ul></>}<p className="muted">{e.origin === "live" ? `Respuesta live · ${e.model}` : "Generación mock · sin gasto"} · {dateText(e.created_at)}</p></>}
          {e.state === "blocked" && <p role="alert">Bloqueada: {e.reason}</p>}
          {e.state === "failed" && <p role="alert">Falló: {failReason(e.reason)}</p>}
        </li>)}
      </ul>
    </ArcDialogContent>
    </ArcDialog>}
  </section>;
}
