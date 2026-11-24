import React, { useCallback, useEffect, useRef, useState } from "react";
import { Button as ArcButton } from "@/components/arc/button/button";
import { Select as ArcSelect } from "@/components/arc/select/select";
import { Textarea as ArcTextarea } from "@/components/arc/textarea/textarea";
import { Dialog as ArcDialog, DialogContent as ArcDialogContent } from "@/components/arc/dialog/dialog";
import { SortableDataTable as ArcTable } from "@/components/arc/sortable-data-table/sortable-data-table";
import { ServicePicker, ToggleSwitch, type ServiceData } from "./services";
import { EmptyState } from "@/components/arc/empty-state/empty-state";
import { notifyToast } from "./toast";

type Api = (path: string, method?: string, body?: unknown) => Promise<ServiceData>;
const errorText = (error: unknown) => error instanceof Error ? error.message : "No se pudo completar la operación.";
const dateText = (value?: string) => value ? new Date(value).toLocaleString("es-CR", {timeZone: "America/Costa_Rica"}) : "Sin fecha";
const stateLabel = (state?: string) => ({completed: "Completado", blocked: "Bloqueado", failed: "Fallido", running: "En curso"} as Record<string, string>)[state || ""] || "En curso";
const stateTone = (state?: string) => state === "completed" ? "active" : state === "failed" ? "deleted" : "inactive";

export function AnalysisPanel({api, refresh = 0}: {api: Api; refresh?: number}) {
  const [items, setItems] = useState<ServiceData[]>([]), [profiles, setProfiles] = useState<ServiceData[]>([]), [total, setTotal] = useState(0), [loading, setLoading] = useState(true), [error, setError] = useState(""), [notice, setNotice] = useState(""), [reload, setReload] = useState(0);
  const [serviceFilter, setServiceFilter] = useState(""), [stateFilter, setStateFilter] = useState(""), [cursors, setCursors] = useState<(string | null)[]>([null]), [next, setNext] = useState<string | null>(null);
  const [creating, setCreating] = useState(false), [serviceId, setServiceId] = useState(""), [profile, setProfile] = useState("event_correlation"), [period, setPeriod] = useState(30), [objective, setObjective] = useState(""), [confirmed, setConfirmed] = useState(false), [saving, setSaving] = useState(false), [formError, setFormError] = useState("");
  const [detail, setDetail] = useState<ServiceData | null>(null);
  const createDialog = useRef<HTMLDialogElement>(null), detailDialog = useRef<HTMLDialogElement>(null), request = useRef(0);
  const profileName = (id?: string) => profiles.find(item => item.id === id)?.name || id || "";
  const selectedProfile = profiles.find(item => item.id === profile);
  const load = useCallback(async () => {
    const seq = ++request.current; setLoading(true);
    const query = new URLSearchParams({limit: "25"});
    if (serviceFilter) query.set("service_id", serviceFilter);
    if (stateFilter) query.set("state", stateFilter);
    if (cursors.at(-1)) query.set("cursor", cursors.at(-1)!);
    try {const result = await api("/lab-analyses?" + query); if (seq === request.current) {setItems(result.items || []); setNext(result.next_cursor || null); setTotal(result.total_count || 0); setError("");}} catch (error) {if (seq === request.current) setError(errorText(error));} finally {if (seq === request.current) setLoading(false);}
  }, [api, serviceFilter, stateFilter, cursors]);
  useEffect(() => {void load(); return () => {request.current++;};}, [load, reload, refresh]);
  useEffect(() => {void api("/lab-analyses/profiles").then(data => setProfiles(data.items || [])).catch(() => {});}, [api]);
  const resetPage = () => setCursors([null]);
  async function create(event: React.FormEvent) {
    event.preventDefault(); setSaving(true); setFormError("");
    try {
      const result = await api("/lab-analyses", "POST", {service_id: serviceId, profile, period_days: period, objective: objective.trim(), confirmed: true});
      setCreating(false); setConfirmed(false); setObjective("");
      const message = result.state === "blocked" ? "Análisis registrado como bloqueado: el perfil todavía no está disponible y no se ejecutó ninguna herramienta." : "Análisis completado con datos ya ingeridos. Ningún resultado aplica cambios.";
      setNotice(message);
      notifyToast(result.state === "blocked" ? "warning" : "success", result.state === "blocked" ? "Análisis bloqueado" : "Análisis completado", message);
      setReload(value => value + 1);
    } catch (error) {setFormError(errorText(error));notifyToast("error","No se pudo crear el análisis",errorText(error));} finally {setSaving(false);}
  }
  async function openDetail(item: ServiceData) {
    setError("");
    try {setDetail(await api("/lab-analyses/" + item.id));} catch (error) {setError(errorText(error));notifyToast("error","No se pudo abrir el análisis",errorText(error));}
  }
  return <section className="service-catalog" aria-labelledby="analysis-heading">
    <div className="list-heading"><div><h2 id="analysis-heading">Análisis</h2><p className="muted">Análisis acotados sobre un servicio del catálogo, con alcance confirmado por una persona. Sentinel observa y explica; no aplica cambios.</p></div><ArcButton onClick={() => {setFormError(""); setCreating(true);}}>Nuevo análisis</ArcButton></div>
    <div className="service-filters analysis-filters"><ServicePicker api={api} value={serviceFilter} onChange={value => {setServiceFilter(value); resetPage();}} refresh={refresh} /><ArcSelect label="Estado" value={stateFilter || "__all__"} onValueChange={v => {setStateFilter(v === "__all__" ? "" : v); resetPage();}} options={[{value:"__all__",label:"Todos los estados"},{value:"completed",label:"Completados"},{value:"blocked",label:"Bloqueados"},{value:"failed",label:"Fallidos"},{value:"running",label:"En curso"}]} /></div>
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {/* UI-ARC-06: sin filas no se renderiza la tabla (su fila "Sin análisis"
        duplicaba el EmptyState y dejaba una tabla vacía gigante). */}
    {(loading || items.length > 0) && <div className="table-scroll" aria-busy={loading}><ArcTable caption="Análisis anteriores" rows={items} rowKey="id" emptyMessage="Sin análisis" columns={[
      {key: "created_at", label: "Fecha", render: (_v, item) => dateText(item.created_at)},
      {key: "service_name", label: "Servicio"},
      {key: "profile", label: "Perfil", render: (_v, item) => profileName(item.profile)},
      {key: "state", label: "Estado", render: (_v, item) => <span className="status-pill" data-state={stateTone(item.state)}>{stateLabel(item.state)}</span>},
      {key: "summary", label: "Resumen", render: (_v, item) => item.summary || "Sin resumen"},
      {key: "actions", label: "Acciones", render: (_v, item) => <ArcButton type="button" variant="secondary" size="sm" onClick={() => void openDetail(item)}>Ver detalle</ArcButton>},
    ]} /></div>}
    {loading && <p role="status">Cargando análisis…</p>}{!loading && !items.length && <div className="analysis-empty"><EmptyState title="Todavía no hay análisis" description="Creá el primero con un servicio del catálogo y un perfil, con el botón «Nuevo análisis»." /></div>}
    <nav className="pagination" aria-label="Páginas de análisis"><span>{total} análisis · Página {cursors.length}</span><ArcButton type="button" variant="secondary" disabled={loading || cursors.length === 1} onClick={() => setCursors(previous => previous.slice(0, -1))}>Anterior</ArcButton><ArcButton type="button" variant="secondary" disabled={loading || !next} onClick={() => next && setCursors(previous => [...previous, next])}>Siguiente</ArcButton></nav>
    <ArcDialog open={creating} onOpenChange={open => {if (!open && !saving) setCreating(false);}}>
    <ArcDialogContent title="Nuevo análisis" className="service-dialog">
      {formError && <p role="alert">{formError}</p>}
      <form onSubmit={create}><fieldset disabled={saving}>
        <ServicePicker api={api} value={serviceId} onChange={setServiceId} label="Servicio a analizar" refresh={refresh} />
        <ArcSelect label="Perfil de análisis" value={profile} onValueChange={setProfile} options={profiles.map(item => ({value: item.id, label: item.name + (item.available ? "" : " (no disponible)")}))} />
        {selectedProfile && <div className="service-confirm"><p>{selectedProfile.description}</p><p className="muted">Límites: {selectedProfile.limits}</p>{!selectedProfile.available && <p>Este perfil se registrará como bloqueado, con la limitación visible. No se ejecutará ninguna herramienta.</p>}</div>}
        <ArcSelect label="Periodo de observación" value={String(period)} onValueChange={v => setPeriod(Number(v))} options={[{value:"7",label:"Últimos 7 días"},{value:"30",label:"Últimos 30 días"},{value:"90",label:"Últimos 90 días"}]} />
        <ArcTextarea label="Objetivo del análisis" maxLength={500} rows={2} value={objective} onChange={event => setObjective(event.target.value)} placeholder="Qué querés averiguar con este análisis" />
        <div className="service-confirm"><p><strong>Alcance exacto.</strong> Destino: únicamente el servicio seleccionado del catálogo, sin rangos, sin otros hosts y sin expansión automática. Actividad: solo lectura de datos ya ingeridos por Sentinel. Sin escaneo activo, sin red externa, sin gasto de IA y sin cambios en ningún sistema.</p></div>
        <div className="switch-row"><span>Confirmo el objetivo y el alcance</span><ToggleSwitch label="Confirmo el objetivo y el alcance" checked={confirmed} onChange={setConfirmed} /></div>
        <div className="service-dialog-actions"><ArcButton type="button" variant="secondary" disabled={saving} onClick={() => setCreating(false)}>Cancelar</ArcButton><ArcButton disabled={saving || !serviceId || !confirmed}>{saving ? "Ejecutando…" : "Crear y ejecutar análisis"}</ArcButton></div>
      </fieldset></form>
    </ArcDialogContent>
    </ArcDialog>
    <ArcDialog open={!!detail} onOpenChange={open => {if (!open) setDetail(null);}}>
    <ArcDialogContent title="Detalle del análisis" className="service-dialog">
      {detail && <div>
        <p><span className="status-pill" data-state={stateTone(detail.state)}>{stateLabel(detail.state)}</span></p>
        <p><strong>Servicio:</strong> {detail.service_name} · <strong>Perfil:</strong> {profileName(detail.profile)} (v{detail.profile_version})</p>
        <p><strong>Creado:</strong> {dateText(detail.created_at)}{detail.finished_at && <> · <strong>Finalizado:</strong> {dateText(detail.finished_at)}</>}</p>
        {detail.objective && <p><strong>Objetivo:</strong> {detail.objective}</p>}
        <p><strong>Alcance:</strong> servicio del catálogo, últimos {detail.scope?.period_days} días, confirmación registrada.</p>
        {detail.summary && <><h3>Resumen</h3><p>{detail.summary}</p></>}
        {detail.stats?.incidents_total !== undefined && <p><strong>Datos:</strong> {detail.stats.incidents_total} incidencia(s) y {detail.stats.records_total} registro(s) en el periodo.</p>}
        {detail.stats?.distinct_src_ips !== undefined && <p><strong>Datos:</strong> {detail.stats.distinct_src_ips} IP(s) origen distinta(s) observadas en el periodo.</p>}
        {!!detail.findings?.length && <><h3>Hallazgos y observaciones</h3><ul>{detail.findings.map((finding: ServiceData, index: number) => <li key={index}><strong>{finding.title}</strong><p className="muted">{finding.detail}</p></li>)}</ul></>}
        {!!detail.limitations?.length && <><h3>Limitaciones</h3><ul>{detail.limitations.map((text: string, index: number) => <li key={index}>{text}</li>)}</ul></>}
      </div>}
    </ArcDialogContent>
    </ArcDialog>
  </section>;
}
