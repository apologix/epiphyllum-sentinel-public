// @vitest-environment jsdom
// UI-ARC-06: contratos de estructura de las correcciones sobre el stack
// real de Allan. Lo visual fino (hover sin shift, drawer visible sin
// scroll, overflow de notificaciones) se verifica en navegador real con
// Playwright + fixtures; acá quedan los contratos de DOM que no deben
// regresar.
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { EventList } from "./main";
import { ServiceCatalog } from "./services";
import { AnalysisPanel } from "./analysis";
import { StreamPanel, WafflePanel } from "./charts05";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); localStorage.clear(); });
const ok = (data: unknown) => ({ ok: true, json: async () => data });

const allEvents = Array.from({ length: 25 }, (_, i) => ({ id: `e${i + 1}`, event_time: "2026-11-22T07:00:00Z", ingested_at: "2026-11-22T07:00:01Z", event_type: "auth.failed", level: "error", service: "Syslog", message: `evento ${i + 1}`, source: "sintética", parser: "sentinel-json", selected_for_analysis: true }));

it("UI-ARC-06: Eventos pagina de a 10 por defecto y el detalle abre en drawer lateral fijo", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (url.includes("/services")) return ok({ items: [], next_cursor: null, total_count: 0 });
    const limit = Number(new URLSearchParams(url.split("?")[1] || "").get("limit") || 25);
    return ok({ items: allEvents.slice(0, limit), next_cursor: "10", total_count: 25 });
  }));
  const { container } = render(<EventList refresh={0} />);
  await waitFor(() => expect(container.querySelectorAll("tbody tr").length).toBe(10));
  fireEvent.click(screen.getAllByRole("button", { name: "Ver" })[0]);
  const drawer = await screen.findByLabelText("Detalle del evento");
  expect(drawer.classList.contains("event-drawer")).toBe(true);
  expect(drawer.textContent).toContain("ID interno");
  expect(container.querySelector(".event-detail-panel")).toBeNull();
});

it("UI-ARC-06: acciones de servicio compactas en una línea, con Eliminar dentro del menú Acciones", async () => {
  const svc = { id: "s1", name: "Nginx principal", description: "d", context: "", enabled: true, version: 1, sources: [] };
  const api = vi.fn(async () => ({ items: [svc], total_count: 1, next_cursor: null }));
  const { container } = render(<ServiceCatalog api={api} />);
  await screen.findByText("Nginx principal");
  const compact = container.querySelector(".service-actions-compact");
  expect(compact).toBeTruthy();
  expect(compact?.querySelectorAll("button").length).toBeGreaterThanOrEqual(2);
  fireEvent.pointerDown(screen.getByRole("button", { name: "Acciones" }));
  expect(await screen.findByRole("menuitem", { name: "Eliminar" })).toBeTruthy();
});

it("UI-ARC-06: el buscador de reglas precede a las incorporadas y no se mueve; una sola regla expandida", async () => {
  const api = vi.fn(async () => ({ items: [], total_count: 0 }));
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", { name: "Agregar servicio" }));
  const search = screen.getByRole("searchbox", { name: "Buscar reglas para incorporar" });
  const incorporated = document.querySelector(".rule-incorporated");
  expect(incorporated).toBeTruthy();
  // El buscador está ANTES de la lista de incorporadas en el DOM: agregar
  // reglas nunca lo desplaza.
  expect(search.compareDocumentPosition(incorporated!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  fireEvent.change(search, { target: { value: "acceso" } });
  fireEvent.click(screen.getByRole("button", { name: /R1: Fallos de acceso/ }));
  // La recién agregada se expande sola: su deslizador está visible.
  expect(await screen.findByRole("slider", { name: "Umbral de R1" })).toBeTruthy();
  fireEvent.change(search, { target: { value: "acceso" } });
  fireEvent.click(screen.getByRole("button", { name: /R2: Acceso tras fallos/ }));
  // Al expandir R2, R1 colapsa (una sola abierta): su deslizador se va,
  // pero su fila colapsada con el resumen queda visible.
  await waitFor(() => expect(screen.queryByRole("slider", { name: "Umbral de R1" })).toBeNull());
  expect(screen.getByRole("slider", { name: "Umbral de R2" })).toBeTruthy();
  expect(screen.getAllByText(/Se activa con 5 o más eventos en 60 segundos/).length).toBeGreaterThan(0);
  // Re-expandir R1 desde su fila colapsada.
  fireEvent.click(screen.getByRole("button", { name: /Configurar regla R1/ }));
  expect(await screen.findByRole("slider", { name: "Umbral de R1" })).toBeTruthy();
  expect(screen.queryByRole("slider", { name: "Umbral de R2" })).toBeNull();
});

it("UI-ARC-06: Análisis con filtros en grilla propia y EmptyState compacto", async () => {
  const api = vi.fn(async (path: string) => path.includes("profiles") ? { items: [] } : path.includes("/services") ? { items: [], total_count: 0, next_cursor: null } : { items: [], total_count: 0, next_cursor: null });
  const { container } = render(<AnalysisPanel api={api} />);
  const filters = container.querySelector(".analysis-filters");
  expect(filters).toBeTruthy();
  expect(filters?.children.length).toBe(2);
  expect(await screen.findByText("Todavía no hay análisis")).toBeTruthy();
});

it("UI-ARC-06: streamgraph y waffle son los componentes reales de Arc", async () => {
  const { container } = render(<>
    <StreamPanel data={[{ key: "d1", label: "lunes", axisLabel: "lun", values: { high: 2 } }, { key: "d2", label: "martes", axisLabel: "mar", values: { high: 5 } }, { key: "d3", label: "miércoles", axisLabel: "mié", values: { high: 3 } }]} series={[{ key: "high", label: "Alta", color: "#f76b15" }]} />
    <WafflePanel data={[{ key: "ssh", label: "OpenSSH", value: 3, color: "#6ea8fe" }, { key: "nginx", label: "Nginx", value: 1, color: "#e8a33d" }]} />
  </>);
  // Waffle real: leyenda con nombre y % (el % rueda con motion y en jsdom
  // queda en la tabla de datos: 3 de 4 = 75 %), y 100 celdas en la grilla.
  expect((await screen.findAllByText("OpenSSH")).length).toBeGreaterThan(0);
  // Las 100 celdas se cuentan en la gira de navegador real (en jsdom el
  // waffle no mide ancho y no pinta la grilla); acá basta la leyenda.
  expect(container.textContent).toContain("75");
  // Stream real: leyenda conmutable con el nombre de la capa.
  expect(screen.getAllByText("Alta").length).toBeGreaterThan(0);
});
