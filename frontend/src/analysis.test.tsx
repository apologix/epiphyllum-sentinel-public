// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AnalysisPanel } from "./analysis";
const profiles = {items: [
  {id: "event_correlation", name: "Correlación con eventos", version: 1, available: true, description: "Relaciona incidencias y registros.", limits: "Solo lectura de datos de Sentinel."},
  {id: "config_audit", name: "Auditoría local de configuración", version: 1, available: false, description: "Hardening de la VM.", limits: "Requiere adaptador fijado."},
]};
const service = {id: "svc-1", name: "nginx", enabled: true, version: 1, source_count: 1};
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  HTMLDialogElement.prototype.showModal = function () {this.setAttribute("open", "");};
  HTMLDialogElement.prototype.close = function () {this.removeAttribute("open");};
});
afterEach(() => {cleanup(); vi.restoreAllMocks();});
function mockApi(extra?: (path: string, method?: string, body?: unknown) => unknown) {
  return vi.fn(async (path: string, method = "GET", body?: unknown): Promise<Record<string, any>> => {
    const handled = extra?.(path, method, body);
    if (handled !== undefined) return handled as Record<string, any>;
    if (path === "/lab-analyses/profiles") return profiles;
    if (path.startsWith("/services?")) return {items: [service], total_count: 1, next_cursor: null};
    if (path === "/services/svc-1") return service;
    if (path.startsWith("/lab-analyses?")) return {items: [], total_count: 0, next_cursor: null};
    return {};
  });
}
it("crea un análisis solo tras confirmar el alcance y lo envía con parámetros cerrados", async () => {
  const api = mockApi((path, method, body) => {
    if (path === "/lab-analyses" && method === "POST") {expect(body).toEqual({service_id: "svc-1", profile: "event_correlation", period_days: 30, objective: "", confirmed: true}); return {id: "a1", state: "completed", summary: "Se correlacionaron 2 incidencia(s)."};}
    return undefined;
  });
  render(<AnalysisPanel api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Nuevo análisis"}));
  fireEvent.pointerDown(screen.getByRole("combobox", {name: "Servicio a analizar"}));
  fireEvent.click(screen.getByRole("combobox", {name: "Servicio a analizar"}));
  fireEvent.click(await screen.findByRole("option", {name: "nginx"}));
  const submit = screen.getByRole("button", {name: "Crear y ejecutar análisis"});
  expect(submit).toHaveProperty("disabled", true);
  fireEvent.click(screen.getByRole("switch", {name: "Confirmo el objetivo y el alcance"}));
  expect(submit).toHaveProperty("disabled", false);
  fireEvent.click(submit);
  expect(await screen.findByText(/Análisis completado con datos ya ingeridos/)).toBeTruthy();
});
it("un perfil no disponible se anuncia como bloqueado antes de crear", async () => {
  const api = mockApi((path, method) => {
    if (path === "/lab-analyses" && method === "POST") return {id: "a2", state: "blocked"};
    return undefined;
  });
  render(<AnalysisPanel api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Nuevo análisis"}));
  fireEvent.pointerDown(screen.getByRole("combobox", {name: "Perfil de análisis"}));
  fireEvent.click(screen.getByRole("combobox", {name: "Perfil de análisis"}));
  fireEvent.click(await screen.findByRole("option", {name: "Auditoría local de configuración (no disponible)"}));
  expect(await screen.findByText(/se registrará como bloqueado/)).toBeTruthy();
  fireEvent.pointerDown(screen.getByRole("combobox", {name: "Servicio a analizar"}));
  fireEvent.click(screen.getByRole("combobox", {name: "Servicio a analizar"}));
  fireEvent.click(await screen.findByRole("option", {name: "nginx"}));
  fireEvent.click(screen.getByRole("switch", {name: "Confirmo el objetivo y el alcance"}));
  fireEvent.click(screen.getByRole("button", {name: "Crear y ejecutar análisis"}));
  expect(await screen.findByText(/registrado como bloqueado/)).toBeTruthy();
});
it("lista análisis anteriores y muestra el detalle con hallazgos y limitaciones", async () => {
  const row = {id: "a1", service_name: "nginx", profile: "event_correlation", profile_version: 1, state: "completed", summary: "Se correlacionaron 2 incidencia(s) vinculadas y 40 registro(s) del servicio en los últimos 30 días.", created_at: "2026-11-20T10:00:00Z", finished_at: "2026-11-20T10:00:01Z", objective: "", scope: {period_days: 30}, stats: {incidents_total: 2, records_total: 40}, findings: [{title: "2 incidencia(s) de la regla R1 en el periodo", detail: "Severidad máxima registrada para esta regla: high."}], limitations: ["Correlación determinista sobre datos ya ingeridos."]};
  const api = mockApi(path => {
    if (path.startsWith("/lab-analyses?")) return {items: [row], total_count: 1, next_cursor: null};
    if (path === "/lab-analyses/a1") return row;
    return undefined;
  });
  render(<AnalysisPanel api={api} />);
  expect(await screen.findByText(/Se correlacionaron 2 incidencia\(s\) vinculadas/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", {name: "Ver detalle"}));
  expect(await screen.findByText("2 incidencia(s) de la regla R1 en el periodo")).toBeTruthy();
  expect(screen.getByText("Correlación determinista sobre datos ya ingeridos.")).toBeTruthy();
  await waitFor(() => expect(api.mock.calls.some(call => call[0] === "/lab-analyses/a1")).toBe(true));
});
