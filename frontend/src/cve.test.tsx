// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { CveTab } from "./cve";

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  HTMLDialogElement.prototype.showModal = function () {this.setAttribute("open", "");};
  HTMLDialogElement.prototype.close = function () {this.removeAttribute("open");};
});
afterEach(() => {cleanup(); vi.restoreAllMocks();});

it("el tab CVE muestra resumen, banner detectado, hallazgos paginados y la respuesta de la IA", async () => {
  const svc1 = {id: "svc-1", name: "apache-httpd", enabled: true, software_product: "apache:http_server", software_version: "2.4.58", software_origin: "operator", check: {state: "completed", total_reported: 12, affecting_count: 8, checked_at: "2026-11-20T12:00:00Z"}};
  const svc2 = {id: "svc-2", name: "nginx-proxy", enabled: true, software_product: null, software_version: null, check: null};
  const findings = Array.from({length: 12}, (_, i) => ({id: `f-${i}`, cve_id: `CVE-2024-${1000 + i}`, severity: i % 2 ? "high" : "critical", base_score: 9.5 - i * 0.1, summary: `Resumen ${i}`, published: "2024-07-01T00:00:00Z", affects: i < 8, affected_range: "desde 2.4.0, hasta antes de 2.4.60", fixed_version: i < 8 ? "2.4.60" : null, service_name: "apache-httpd", product: "apache:http_server", version: "2.4.58", refs: []}));
  let asked = false;
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (path === "/cve/services") return {daily_enabled: true, items: [svc1, svc2]};
    if (path.startsWith("/services?")) return {items: [svc1, svc2], total_count: 2};
    if (path === "/services/svc-2/cve/banner-suggestions") return {records_scanned: 40, suggestions: [{product: "nginx:nginx", version: "1.24.0", records: 17}]};
    if (path.startsWith("/cve/findings?")) {
      const params = new URLSearchParams(path.split("?")[1]);
      const limit = Number(params.get("limit") || 10), offset = Number(params.get("offset") || 0);
      return {items: findings.slice(offset, offset + limit), total_count: findings.length, limit, offset};
    }
    if (path === "/cve-findings/f-0/explanations" && method === "POST") {asked = true; return {id: "e-1", state: "pending", question: (body as {question: string}).question};}
    if (path === "/cve-findings/f-0/explanations") return {items: asked ? [{id: "e-1", state: "ready", question: "¿Cómo me afecta esta vulnerabilidad y cómo la puedo solucionar?", answer: "Generación mock: explicación de prueba con la corrección 2.4.60.", human_checks: ["Verificar la versión instalada."], origin: "mock", model: "mock-v1", created_at: "2026-11-21T00:00:00Z"}] : []};
    throw new Error("unexpected " + method + " " + path);
  });
  render(<CveTab api={api as never} />);
  expect(await screen.findByText(/Worker pasivo:/)).toBeTruthy();
  expect(await screen.findByText(/Detectado en banners:/)).toBeTruthy();
  expect(screen.getByText("nginx:nginx 1.24.0")).toBeTruthy();
  expect(screen.getByText(/sugerencia: no se aplica automáticamente/)).toBeTruthy();
  expect(screen.queryByRole("button", {name: "Usar esta versión"})).toBeNull();
  expect(screen.getByText("declarado")).toBeTruthy();
  expect(await screen.findByText("12 hallazgos · Página 1 de 2")).toBeTruthy();
  expect(screen.getByText("CVE-2024-1000")).toBeTruthy();
  expect(screen.queryByText("CVE-2024-1011")).toBeNull();
  const nav = screen.getByRole("navigation", {name: "Páginas de hallazgos CVE"});
  fireEvent.click(within(nav).getByRole("button", {name: "Siguiente"}));
  expect(await screen.findByText("12 hallazgos · Página 2 de 2")).toBeTruthy();
  expect(screen.getByText("CVE-2024-1011")).toBeTruthy();
  fireEvent.click(within(nav).getByRole("button", {name: "Anterior"}));
  expect(await screen.findByText("12 hallazgos · Página 1 de 2")).toBeTruthy();
  const row = screen.getByText("CVE-2024-1000").closest("tr")!;
  fireEvent.click(within(row as HTMLElement).getByRole("button", {name: "Preguntar a la IA"}));
  expect(await screen.findByText(/La IA responde solo con el contexto/)).toBeTruthy();
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", {name: "Preguntar a la IA"}));
  expect(await screen.findByText(/explicación de prueba con la corrección 2.4.60/)).toBeTruthy();
  expect(screen.getByText("Verificar la versión instalada.")).toBeTruthy();
  expect(screen.getByText(/Generación mock · sin gasto/)).toBeTruthy();
});

it("comprobar todo muestra una notificación toast y la tabla conserva su tamaño con filas de relleno", async () => {
  const svc = {id: "svc-1", name: "apache-httpd", enabled: true, software_product: "apache:http_server", software_version: "2.4.58", software_origin: "operator", check: {state: "completed", total_reported: 2, affecting_count: 2, checked_at: "2026-11-21T12:00:00Z"}};
  const findings = [
    {id: "f-1", cve_id: "CVE-2024-38476", severity: "critical", base_score: 9.8, summary: "Uno", published: "2024-07-01T00:00:00Z", affects: true, fixed_version: "2.4.60", service_name: "apache-httpd", product: "apache:http_server", version: "2.4.58", refs: []},
    {id: "f-2", cve_id: "CVE-2024-38474", severity: "high", base_score: 8.1, summary: "Dos", published: "2024-07-01T00:00:00Z", affects: true, fixed_version: "2.4.60", service_name: "apache-httpd", product: "apache:http_server", version: "2.4.58", refs: []},
  ];
  const api = vi.fn(async (path: string, method = "GET") => {
    if (path === "/cve/services") return {daily_enabled: true, items: [svc]};
    if (path.startsWith("/cve/findings?")) return {items: findings, total_count: findings.length, limit: 10, offset: 0};
    if (path === "/cve/checks/run-all" && method === "POST") return {results: [{service_id: "svc-1", state: "completed"}]};
    throw new Error("unexpected " + method + " " + path);
  });
  const {container} = render(<CveTab api={api as never} />);
  expect(await screen.findByText("CVE-2024-38476")).toBeTruthy();
  const findingsTable = [...container.querySelectorAll("table")].find(t => t.querySelector("caption")?.textContent?.includes("Hallazgos"));
  expect(findingsTable?.querySelectorAll("tbody tr").length).toBe(10); // 2 hallazgos + 8 filas de relleno hasta el tamaño de página
  fireEvent.click(screen.getByRole("button", {name: "Comprobar todo ahora"}));
  const toast = await screen.findByText(/Comprobación terminada: 1 de 1 servicios consultados en NVD/);
  expect(toast.closest(".toast")).toBeTruthy();
});
