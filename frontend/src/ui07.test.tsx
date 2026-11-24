// @vitest-environment jsdom
// UI-ARC-07: contratos de DOM de la tercera corrección sobre el stack
// real de Allan. La interacción fina (clicks reales, alineaciones en px,
// las 3 variantes del donut renderizadas) se verifica en navegador real
// con Playwright + fixtures; acá quedan los contratos que no deben
// regresar: toggle de regla desde toda la cabecera, controles internos
// que no togglean, cascada del donut CVE y estructura de la pestaña CVE.
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { RulePicker } from "./services";
import { CveTab } from "./cve";

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  HTMLDialogElement.prototype.showModal = function () {this.setAttribute("open", "");};
  HTMLDialogElement.prototype.close = function () {this.removeAttribute("open");};
});
afterEach(() => {cleanup(); vi.restoreAllMocks();});

const rule = (id: string, extra: Record<string, unknown> = {}) => ({id, enabled: true, threshold: id === "R1" ? 5 : 5, window_seconds: id === "R1" ? 60 : 120, ...extra});

it("UI-ARC-07: la cabecera completa de la regla toggla el acordeón, una sola expandida", () => {
  const onRules = vi.fn();
  render(<RulePicker rules={[rule("R1"), rule("R2")]} onRules={onRules} sourceKind="folder" />);
  // Colapsadas al inicio: sin opciones visibles.
  expect(screen.queryByLabelText("Umbral de R1")).toBeNull();
  // Click sobre el TEXTO RESUMEN de la cabecera (no sobre un botón puntual):
  // toda la fila es la superficie de toggle.
  fireEvent.click(screen.getByText(/Se activa con 5 o más eventos en 60 segundos/));
  expect(screen.getByRole("button", {name: "Colapsar regla R1"})).toBeTruthy();
  expect(screen.getByLabelText("Umbral de R1")).toBeTruthy();
  // Expandir R2 colapsa R1 (una sola a la vez).
  fireEvent.click(screen.getByText(/Se activa con 5 o más eventos en 120 segundos/));
  expect(screen.getByRole("button", {name: "Colapsar regla R2"})).toBeTruthy();
  expect(screen.getByRole("button", {name: "Configurar regla R1"})).toBeTruthy();
  expect(screen.queryByLabelText("Umbral de R1")).toBeNull();
  // Click de nuevo sobre la cabecera de R2: colapsa.
  fireEvent.click(screen.getByText(/R2: Acceso tras fallos/));
  expect(screen.getByRole("button", {name: "Configurar regla R2"})).toBeTruthy();
  expect(screen.queryByLabelText("Umbral de R2")).toBeNull();
});

it("UI-ARC-07: switch y Quitar de la regla NO disparan el toggle del acordeón", () => {
  const onRules = vi.fn();
  render(<RulePicker rules={[rule("R1"), rule("R2")]} onRules={onRules} sourceKind="folder" />);
  fireEvent.click(screen.getByText(/R1: Fallos de acceso/));
  expect(screen.getByLabelText("Umbral de R1")).toBeTruthy();
  // El switch llama a onRules pero la expansión se mantiene.
  fireEvent.click(screen.getByRole("switch", {name: /R1: Fallos de acceso/}));
  expect(onRules).toHaveBeenCalled();
  expect(screen.getByLabelText("Umbral de R1")).toBeTruthy();
  expect(screen.getByRole("button", {name: "Colapsar regla R1"})).toBeTruthy();
  // Quitar otra regla tampoco toggla la expandida.
  fireEvent.click(screen.getByRole("button", {name: "Quitar regla R2"}));
  expect(onRules).toHaveBeenLastCalledWith([expect.objectContaining({id: "R1"})]);
  expect(screen.getByLabelText("Umbral de R1")).toBeTruthy();
});

it("UI-ARC-07: las opciones de la regla incluyen el select Severidad inicial con su valor", () => {
  const onRules = vi.fn();
  render(<RulePicker rules={[rule("encoded_path_traversal", {threshold: 1, window_seconds: 300, severity: "medium"})]} onRules={onRules} sourceKind="folder" />);
  fireEvent.click(screen.getByText(/encoded_path_traversal: Intento de path traversal/));
  const options = document.querySelector(".rule-options");
  expect(options?.textContent).toContain("Severidad inicial");
  expect(options?.textContent).toContain("Media");
  // El chevron ya no es un glifo de texto: es un icono SVG de Lucide.
  expect(document.querySelector(".rule-toggle-chevron svg")).toBeTruthy();
});

// ---------- Donut CVE en cascada ----------
type Finding = Record<string, unknown>;
const mkServices = (checkedAffecting: number | null) => {
  const base = (id: string, name: string) => ({id, name, enabled: true, software_product: null, software_version: null, software_origin: null, check: null});
  const items: Record<string, unknown>[] = [
    {...base("svc-nginx", "Nginx laboratorio Docker"), software_product: "nginx:nginx", software_version: "1.27.5", software_origin: "operator", check: {state: "completed", total_reported: 0, affecting_count: 0, checked_at: "2026-11-22T09:44:55Z"}},
    base("svc-apache", "Carpeta pública · Apache error"),
    base("svc-haproxy", "Carpeta pública · HAProxy"),
    base("svc-http", "Carpeta pública · HTTP combined"),
    base("svc-nginx-err", "Carpeta pública · Nginx error"),
    base("svc-ssh", "Carpeta pública · OpenSSH auth"),
    base("svc-syslog", "Carpeta pública · Syslog"),
  ];
  if (checkedAffecting !== null) items[0] = {...items[0], check: {state: "completed", total_reported: 9, affecting_count: checkedAffecting, checked_at: "2026-11-22T09:44:55Z"}};
  return items;
};
const finding = (id: string, severity: string, affects: boolean): Finding => ({id, cve_id: `CVE-2024-200${id}`, severity, base_score: 7.5, summary: "Resumen", published: "2024-07-01T00:00:00Z", affects, fixed_version: null, service_name: "Nginx laboratorio Docker", product: "nginx:nginx", version: "1.27.5", refs: []});
function cveApi(services: unknown[], affectsItems: Finding[], allItems: Finding[]) {
  return vi.fn(async (path: string) => {
    if (path === "/cve/services") return {daily_enabled: true, items: services};
    if (path.startsWith("/services?")) return {items: services, total_count: services.length};
    if (path.includes("/cve/banner-suggestions")) return {records_scanned: 2, suggestions: [{product: "apache:http_server", version: "2.4.58", records: 2}]};
    if (path.startsWith("/cve/findings?")) {
      const params = new URLSearchParams(path.split("?")[1]);
      const limit = Number(params.get("limit") || 10), offset = Number(params.get("offset") || 0);
      const pool = params.get("affects") === "true" ? affectsItems : allItems;
      return {items: pool.slice(offset, offset + limit), total_count: pool.length};
    }
    throw new Error("unexpected " + path);
  });
}

it("UI-ARC-07: donut CVE escenario 1 — hallazgos que afectan por severidad", async () => {
  const affects = [finding("1", "critical", true), finding("2", "high", true), finding("3", "high", true)];
  render(<CveTab api={cveApi(mkServices(3), affects, affects) as never} />);
  expect(await screen.findByRole("heading", {name: "Hallazgos que te afectan, por severidad"})).toBeTruthy();
  expect(document.querySelector(".cve-donut figure")).toBeTruthy();
});

it("UI-ARC-07: donut CVE escenario 2 — hallazgos sin afectar por severidad", async () => {
  const all = [finding("1", "medium", false), finding("2", "low", false)];
  render(<CveTab api={cveApi(mkServices(0), [], all) as never} />);
  expect(await screen.findByRole("heading", {name: "Hallazgos de la última comprobación, por severidad"})).toBeTruthy();
  expect(screen.getByText(/Ninguno de estos hallazgos afecta a tus versiones declaradas/)).toBeTruthy();
  expect(document.querySelector(".cve-donut figure")).toBeTruthy();
});

it("UI-ARC-07: donut CVE escenario 3 — sin hallazgos, cobertura «1 de 7» y estructura de la pestaña", async () => {
  const {container} = render(<CveTab api={cveApi(mkServices(null), [], []) as never} />);
  expect(await screen.findByRole("heading", {name: "Cobertura de comprobación"})).toBeTruthy();
  // El centro del donut muestra la fracción de cobertura (el KPI también
  // dice «1 de 7»: se busca acotado a la tarjeta del donut).
  expect(container.querySelector(".cve-donut")?.textContent).toContain("1 de 7");
  expect(document.querySelector(".cve-donut figure")).toBeTruthy();
  // La leyenda trae los conteos reales (el texto aparece en la leyenda,
  // el centro y la tabla accesible del gráfico: basta con que exista).
  expect(screen.getAllByText("Comprobados").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Pendientes de comprobar").length).toBeGreaterThan(0);
  // (2b) La nota del worker vive bajo el título, no como bloque suelto.
  expect(container.querySelector(".list-heading .cve-worker-note")?.textContent).toContain("Worker pasivo:");
  // (2c) Limpiar filtros dentro de su celda de alineación.
  expect(container.querySelector(".cve-filter-action")?.textContent).toContain("Limpiar filtros");
  // (2d) Sin tabla de hallazgos vacía: solo el EmptyState compacto.
  expect(screen.queryByText("Sin hallazgos")).toBeNull();
  expect(screen.getByText("No hay hallazgos con esos filtros")).toBeTruthy();
});
