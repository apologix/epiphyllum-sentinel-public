// @vitest-environment jsdom
// CVE-07: la pantalla CVE distingue la versión confirmada por cada vía y
// vincula los resultados a la versión ACTUAL del servicio. Fixtures con
// la forma del taller: Docker con versión manual (operator), VM con
// versión vía MCP, un servicio que cambió de versión (A -> B, pendiente)
// y uno sin versión (su version.json no validó: el backend no le asignó
// software y la UI no ofrece comprobarlo ni consulta NVD por él).
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { CveTab } from "./cve";

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  HTMLDialogElement.prototype.showModal = function () {this.setAttribute("open", "");};
  HTMLDialogElement.prototype.close = function () {this.removeAttribute("open");};
});
afterEach(() => {cleanup(); vi.restoreAllMocks();});

const services = [
  {id: "svc-docker", name: "Nginx laboratorio Docker", enabled: true, software_product: "nginx:nginx", software_version: "1.27.5", software_origin: "operator", check: {state: "completed", product: "nginx:nginx", version: "1.27.5", total_reported: 0, affecting_count: 0, checked_at: "2026-11-22T09:44:55Z"}, previous_check: null},
  {id: "svc-vm", name: "Nginx laboratorio VM", enabled: true, software_product: "f5:nginx", software_version: "1.26.3", software_origin: "mcp", check: {state: "completed", product: "f5:nginx", version: "1.26.3", total_reported: 3, affecting_count: 1, checked_at: "2026-11-22T10:00:00Z"}, previous_check: null},
  {id: "svc-changed", name: "Apache del taller", enabled: true, software_product: "apache:http_server", software_version: "2.4.62", software_origin: "operator", check: null, previous_check: {product: "apache:http_server", version: "2.4.58", state: "completed", checked_at: "2026-11-21T10:00:00Z"}},
  {id: "svc-noversion", name: "MySQL laboratorio VM", enabled: true, software_product: null, software_version: null, software_origin: null, check: null, previous_check: null},
];

function api() {
  return vi.fn(async (path: string) => {
    if (path === "/cve/services") return {daily_enabled: true, items: services};
    if (path.startsWith("/services?")) return {items: services, total_count: services.length};
    if (path.includes("/cve/banner-suggestions")) return {records_scanned: 0, suggestions: []};
    if (path.startsWith("/cve/findings?")) return {items: [], total_count: 0};
    throw new Error("unexpected " + path);
  });
}

it("CVE-07: cada servicio muestra su versión y su procedencia sin mezclarlas", async () => {
  render(<CveTab api={api() as never} />);
  expect(await screen.findByText("vía MCP")).toBeTruthy();
  expect(screen.getByText("f5:nginx")).toBeTruthy();
  expect(screen.getByText("1.26.3")).toBeTruthy();
  expect(screen.getByText("nginx:nginx")).toBeTruthy();
  expect(screen.getByText("1.27.5")).toBeTruthy();
  // La nota del worker ya no promete adopción de banners.
  expect(screen.getByText(/nunca se aplican automáticamente/)).toBeTruthy();
  expect(screen.queryByText(/se adoptará automáticamente/)).toBeNull();
});

it("CVE-07: cambio de versión A -> B deja el servicio pendiente y el dato anterior accesible", async () => {
  render(<CveTab api={api() as never} />);
  expect(await screen.findByText("Pendiente de comprobar")).toBeTruthy();
  expect(screen.getByText(/El último chequeo fue para apache:http_server 2.4.58/)).toBeTruthy();
  // El chequeo vigente muestra para qué producto/versión se consultó.
  expect(screen.getByText("para f5:nginx 1.26.3")).toBeTruthy();
});

it("CVE-07: sin versión no hay botón de comprobar ni consulta asociada", async () => {
  render(<CveTab api={api() as never} />);
  expect(await screen.findByText("Sin versión")).toBeTruthy();
  const buttons = screen.getAllByRole("button", {name: "Comprobar"});
  // Solo Docker, VM y el pendiente (tienen software actual) pueden comprobarse.
  expect(buttons.length).toBe(3);
});
