// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ServiceCatalog, ServicePicker } from "./services";

// Los selectores y menús de Arc (Radix) se abren con pointerDown y se elige
// la opción/ítem; estas ayudas replican esa interacción en las pruebas.
async function pickOption(name: string, option: string, scope?: HTMLElement) {
  const box = scope ? within(scope).getByRole("combobox", {name}) : screen.getByRole("combobox", {name});
  fireEvent.pointerDown(box);
  fireEvent.click(box);
  fireEvent.click(await screen.findByRole("option", {name: option}));
}
async function pickMenu(trigger: string, item: string) {
  fireEvent.pointerDown(screen.getByRole("button", {name: trigger}));
  fireEvent.click(await screen.findByRole("menuitem", {name: item}));
}
const first = {id: "first", name: "Nginx principal", description: "Proxy sintético", context: "Los 404 aislados son esperados.", enabled: true, version: 1, source_count: 0};
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  HTMLDialogElement.prototype.showModal = function () {this.setAttribute("open", "");};
  HTMLDialogElement.prototype.close = function () {this.removeAttribute("open");};
});
afterEach(() => {cleanup(); vi.restoreAllMocks();});
it("pagina servicios en servidor y reinicia el cursor al buscar", async () => {
  const api = vi.fn(async (path: string) => path.includes("cursor=next") ? {items: [{...first, id: "second", name: "Servicio segunda página"}], total_count: 11, next_cursor: null} : {items: [first], total_count: 11, next_cursor: "next"});
  render(<ServiceCatalog api={api} />);
  expect(await screen.findByText(first.name)).toBeTruthy();
  const pages = screen.getByRole("navigation", {name: "Páginas de servicios"});
  fireEvent.click(within(pages).getByRole("button", {name: "Siguiente"}));
  expect(await screen.findByText("Servicio segunda página")).toBeTruthy();
  expect(screen.queryByText(first.name)).toBeNull();
  fireEvent.change(screen.getByRole("searchbox", {name: "Buscar servicios"}), {target: {value: "nginx"}});
  await waitFor(() => expect(api.mock.calls.at(-1)?.[0]).toContain("q=nginx"));
  expect(api.mock.calls.at(-1)?.[0]).not.toContain("cursor=");
});
it("crea servicio con fuente inactiva y mantiene el error de versión visible", async () => {
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (method === "POST") {expect(body).toMatchObject({name: "Nginx personalizado", source: {kind: "folder", enabled: false, config: {root_alias: "demo-logs", directory: "nginx", selector: "nginx.log"}}}); throw new Error("El servicio cambió; recargá su versión.");}
    return {items: [], total_count: 0};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.change(screen.getByRole("textbox", {name: "Nombre del servicio"}), {target: {value: "Nginx personalizado"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Directorio del servicio"}), {target: {value: "nginx"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Archivo o patrón"}), {target: {value: "nginx.log"}});
  fireEvent.click(screen.getByRole("button", {name: "Guardar servicio"}));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "El servicio cambió; recargá su versión.");
  expect(screen.getByRole("textbox", {name: "Nombre del servicio"})).toHaveProperty("value", "Nginx personalizado");
  fireEvent.click(screen.getByRole("button", {name: "Cancelar"}));
  expect(await screen.findByText("Hay cambios sin guardar. ¿Querés descartarlos?")).toBeTruthy();
  expect(document.activeElement).toBe(screen.getByText("Hay cambios sin guardar. ¿Querés descartarlos?").parentElement);
  fireEvent.click(screen.getByRole("button", {name: "Descartar cambios"}));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});
it("desactiva preservando contexto y versión obtenidos del detalle", async () => {
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (method === "PUT") {expect(body).toMatchObject({expected_version: 2, context: first.context, enabled: false}); return {...first, enabled: false};}
    if (path === "/services/first") return {...first, version: 2};
    return {items: [{...first, context: undefined}], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(await screen.findByRole("switch", {name: "Desactivar Nginx principal"}));
  expect(await screen.findByText("Servicio desactivado. Las tareas ya enviadas finalizarán y conservarán su costo.")).toBeTruthy();
  expect(api.mock.calls.filter(call => call[1] === "PUT")).toHaveLength(1);
});
it("elimina con confirmación y conserva una explicación del historial", async () => {
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (method === "DELETE") {expect(body).toEqual({expected_version: 1}); return {};}
    if (path === "/services/first") return first;
    return {items: [first], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  await screen.findByText(first.name);
  await pickMenu("Acciones", "Eliminar");
  expect(await screen.findByText(/Se conservarán logs, incidencias, conversaciones y costos/)).toBeTruthy();
  expect(api.mock.calls.some(call => call[1] === "DELETE")).toBe(false);
  fireEvent.click(await screen.findByRole("button", {name: "Confirmar eliminación"}));
  expect(await screen.findByText("Servicio eliminado del catálogo operativo. Su historial se conserva.")).toBeTruthy();
});
it("selector usa UUID, muestra servicios inactivos y pagina sin descargar todo", async () => {
  const onChange = vi.fn();
  const api = vi.fn(async (path: string) => ({items: [{...first, enabled: false}], next_cursor: "next", total_count: 1000}));
  render(<ServicePicker api={api} value="" onChange={onChange} />);
  await pickOption("Servicio", "Nginx principal (inactivo)");
  expect(onChange).toHaveBeenCalledWith("first");
  expect(api.mock.calls).toHaveLength(1);
  expect(api.mock.calls[0][0]).toContain("limit=25");
  fireEvent.click(screen.getByRole("button", {name: "Más servicios", hidden: true}));
  await waitFor(() => expect(api.mock.calls.at(-1)?.[0]).toContain("cursor=next"));
});
it("texto de nombre y contexto hostiles quedan escapados", async () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const api = vi.fn(async () => ({items: [{...first, name: hostile}], total_count: 1}));
  const {container} = render(<ServiceCatalog api={api} />);
  expect(await screen.findByText(hostile)).toBeTruthy();
  expect(container.querySelector("img")).toBeNull();
});

it("configura origen externo sin insertar rutas del host y conserva su clasificación", async () => {
  const api = vi.fn(async (_path: string, method = "GET", body?: unknown) => {
    if (method === "POST") {expect(body).toMatchObject({source: {kind: "folder", enabled: false, config: {root_alias: "external", data_class: "real", directory: "nginx", selector: "*.log"}}}); return {};}
    return {items: [], total_count: 0};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.change(screen.getByRole("textbox", {name: "Nombre del servicio"}), {target: {value: "Nginx"}});
  await pickOption("Origen de los registros", "Carpeta del equipo: registros reales");
  expect(screen.getByText(/Guardar esta fuente no monta carpetas/)).toBeTruthy();
  fireEvent.change(screen.getByRole("textbox", {name: "Directorio del servicio"}), {target: {value: "nginx"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Archivo o patrón"}), {target: {value: "*.log"}});
  fireEvent.click(screen.getByRole("button", {name: "Guardar servicio"}));
  await waitFor(() => expect(api.mock.calls.some(call => call[1] === "POST")).toBe(true));
});

it("volver al origen sintético elimina la marca de datos reales", async () => {
  const api = vi.fn(async (_path: string, method = "GET", body?: unknown) => {
    if (method === "POST") {const config = (body as {source: {config: Record<string, unknown>}}).source.config; expect(config.root_alias).toBe("demo-logs"); expect(config).not.toHaveProperty("data_class"); return {};}
    return {items: [], total_count: 0};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.change(screen.getByRole("textbox", {name: "Nombre del servicio"}), {target: {value: "Demo"}});
  await pickOption("Origen de los registros", "Carpeta del equipo: registros reales");
  await pickOption("Origen de los registros", "Demo: registros sintéticos");
  fireEvent.change(screen.getByRole("textbox", {name: "Archivo o patrón"}), {target: {value: "*.log"}});
  fireEvent.click(screen.getByRole("button", {name: "Guardar servicio"}));
  await waitFor(() => expect(api.mock.calls.some(call => call[1] === "POST")).toBe(true));
});

it("comprueba una fuente montada sólo por acción explícita y sin enviar contenido", async () => {
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (path === "/services/first") return first;
    if (path.startsWith("/services/first/sources")) return {items: [{id: "source-1", kind: "folder", enabled: false, version: 1, config: {root_alias: "external", data_class: "real", directory: "", selector: "*.log"}}], total_count: 1};
    if (path === "/sources/source-1/check") {expect(method).toBe("POST"); expect(body).toEqual({}); return {readable: true, matching_files: 2, limited: false};}
    return {items: [first], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  const button = await screen.findByRole("button", {name: "Comprobar lectura"});
  expect(api.mock.calls.some(call => call[0] === "/sources/source-1/check")).toBe(false);
  fireEvent.click(button);
  expect(await screen.findByText("2 archivos disponibles. No se envió contenido al proveedor.")).toBeTruthy();
  expect(api.mock.calls.filter(call => call[0] === "/sources/source-1/check")).toHaveLength(1);
});

it("guarda interpretación y reglas cerradas de una fuente", async () => {
  const api = vi.fn(async (_path: string, method = "GET", body?: unknown) => {
    if (method === "POST") {expect(body).toMatchObject({source: {analysis: {system: "OpenSSH", protocol: "SSH", adapter: "native-text", rules: [{id: "R1", enabled: true, threshold: 5, window_seconds: 60, condition: {field: "level", operator: "eq", value: "error"}}]}}}); return {};}
    return {items: [], total_count: 0};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.change(screen.getByRole("textbox", {name: "Nombre del servicio"}), {target: {value: "SSH"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Archivo o patrón"}), {target: {value: "auth.log"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Sistema de la fuente"}), {target: {value: "OpenSSH"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Protocolo de la fuente"}), {target: {value: "SSH"}});
  await pickOption("Adaptador", "Texto nativo conocido");
  fireEvent.change(screen.getByRole("searchbox", {name: "Buscar reglas para incorporar"}), {target: {value: "acceso"}});
  fireEvent.click(screen.getByRole("button", {name: /R1: Fallos de acceso/}));
  fireEvent.click(screen.getByRole("switch", {name: "Agregar condición"}));
  fireEvent.click(screen.getByRole("button", {name: "Guardar servicio"}));
  await waitFor(() => expect(api.mock.calls.some(call => call[1] === "POST")).toBe(true));
});

it("crea una regla específica del operador y la guarda con la fuente", async () => {
  let posted: any;
  const api = vi.fn(async (_path: string, method = "GET", body?: any) => {
    if (method === "POST") { posted = body; return {}; }
    return {items: [], total_count: 0};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.change(screen.getByRole("textbox", {name: "Nombre del servicio"}), {target: {value: "SSH"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Archivo o patrón"}), {target: {value: "auth.log"}});
  fireEvent.click(screen.getByRole("button", {name: /Crear una regla específica/}));
  fireEvent.change(screen.getByRole("textbox", {name: "Nombre de tu regla específica"}), {target: {value: "Gritos de ayuda en el login"}});
  await pickOption("Qué cuenta la regla", "Accesos aceptados");
  fireEvent.click(screen.getByRole("button", {name: "Agregar regla específica"}));
  expect(await screen.findByText("Gritos de ayuda en el login")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", {name: "Guardar servicio"}));
  await waitFor(() => expect(posted).toBeTruthy());
  const rule = posted.source.analysis.rules.find((item: any) => String(item.id).startsWith("custom:"));
  expect(rule).toMatchObject({name: "Gritos de ayuda en el login", signal: "auth.success", enabled: true, threshold: 5, window_seconds: 300, severity: "medium"});
  expect(rule.id).toMatch(/^custom:gritos-de-ayuda-en-el-login-[a-z0-9]{4}$/);
});

it("configura MCP incremental de laboratorio con datos reales y fuente inactiva", async () => {
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (method === "POST" && path === "/services/first/sources") {expect(body).toMatchObject({kind: "mcp", enabled: false, credential: "token-ficticio", config: {endpoint: "https://192.168.122.210/mcp", mode: "incremental_lab", resource_uri: "logs://nginx/access", synthetic: false, poll_seconds: 5}}); return {};}
    if (path === "/services/first") return first;
    if (path.startsWith("/services/first/sources")) return {items: [], total_count: 0};
    return {items: [first], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  await screen.findByText("Fuentes del servicio");
  await pickMenu("Agregar fuente", "MCP de lectura");
  await pickOption("Modo MCP", "Laboratorio incremental");
  fireEvent.change(screen.getByRole("textbox", {name: "Endpoint MCP"}), {target: {value: "https://192.168.122.210/mcp"}});
  fireEvent.change(screen.getByLabelText("Credencial MCP"), {target: {value: "token-ficticio"}});
  fireEvent.click(screen.getByRole("button", {name: "Guardar nueva fuente"}));
  await waitFor(() => expect(api.mock.calls.some(call => call[1] === "POST" && call[0] === "/services/first/sources")).toBe(true));
});

it("agrega una fuente desde un segundo modal con el tipo elegido en el menú", async () => {
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (method === "POST" && path === "/services/first/sources") {expect(body).toMatchObject({kind: "mcp", enabled: false, config: {endpoint: "https://192.168.122.210/mcp"}}); return {};}
    if (path === "/services/first") return first;
    if (path.startsWith("/services/first/sources")) return {items: [], total_count: 0};
    return {items: [first], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  await screen.findByText("Fuentes del servicio");
  await pickMenu("Agregar fuente", "MCP de lectura");
  expect(await screen.findByText("Agregar fuente · MCP de lectura")).toBeTruthy();
  fireEvent.change(screen.getByRole("textbox", {name: "Endpoint MCP"}), {target: {value: "https://192.168.122.210/mcp"}});
  fireEvent.change(screen.getByRole("textbox", {name: "Recurso de logs"}), {target: {value: "logs://nginx/access"}});
  fireEvent.click(screen.getByRole("button", {name: "Guardar nueva fuente"}));
  await waitFor(() => expect(api.mock.calls.some(call => call[0] === "/services/first/sources" && call[1] === "POST")).toBe(true));
});

it("ajusta el umbral de una regla con el deslizador y resume el disparo en lenguaje claro", async () => {
  const api = vi.fn(async () => ({items: [], total_count: 0}));
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.change(screen.getByRole("searchbox", {name: "Buscar reglas para incorporar"}), {target: {value: "errores"}});
  fireEvent.click(screen.getByRole("button", {name: /R3: Errores HTTP/}));
  expect(await screen.findByText("Se activa con 10 o más eventos en 30 segundos.")).toBeTruthy();
  fireEvent.keyDown(screen.getByRole("slider", {name: "Umbral de R3"}), {key: "PageUp"});
  expect(await screen.findByText("Se activa con 20 o más eventos en 30 segundos.")).toBeTruthy();
});

it("busca reglas con autocompletado, agrega solo la elegida, colapsa al desactivar y quita la regla", async () => {
  const api = vi.fn(async () => ({items: [], total_count: 0}));
  render(<ServiceCatalog api={api} />);
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  const search = screen.getByRole("searchbox", {name: "Buscar reglas para incorporar"});
  fireEvent.change(search, {target: {value: "acceso"}});
  expect(screen.getByRole("button", {name: /R1: Fallos de acceso/})).toBeTruthy();
  expect(screen.getByRole("button", {name: /R2: Acceso tras fallos/})).toBeTruthy();
  expect(screen.queryByRole("button", {name: /R3: Errores HTTP/})).toBeNull();
  fireEvent.click(screen.getByRole("button", {name: /R2: Acceso tras fallos/}));
  expect(await screen.findByText("Se activa con 5 o más eventos en 120 segundos.")).toBeTruthy();
  expect(screen.queryByRole("button", {name: /R2: Acceso tras fallos/})).toBeNull();
  fireEvent.click(screen.getByRole("switch", {name: "R2: Acceso tras fallos"}));
  expect(screen.queryByRole("slider", {name: "Umbral de R2"})).toBeNull();
  expect(screen.getByText(/Regla inactiva: no detecta/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", {name: "Quitar regla R2"}));
  expect(screen.queryByText(/Regla inactiva: no detecta/)).toBeNull();
  // UI-ARC-05: sin búsqueda no se listan reglas; al buscar, R2 vuelve a ofrecerse.
  expect(screen.queryByRole("button", {name: /R2: Acceso tras fallos/})).toBeNull();
  fireEvent.change(search, {target: {value: "acceso"}});
  expect(screen.getByRole("button", {name: /R2: Acceso tras fallos/})).toBeTruthy();
});

it("cerrar el servicio funciona después de guardar una fuente editada, sin pedir descarte", async () => {
  const sourceItem = {id: "source-1", kind: "folder", enabled: false, version: 1, config: {root_alias: "demo-logs", directory: "nginx", selector: "nginx.log"}, analysis: {system: "Nginx", protocol: "HTTP", adapter: "auto", context: "", rules: []}};
  const api = vi.fn(async (path: string, method = "GET") => {
    if (method === "PUT" && path === "/sources/source-1") return {};
    if (path === "/services/first") return first;
    if (path.startsWith("/services/first/sources")) return {items: [sourceItem], total_count: 1};
    return {items: [first], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  fireEvent.click(await screen.findByRole("button", {name: "Editar fuente"}));
  fireEvent.change(screen.getByRole("textbox", {name: "Archivo o patrón"}), {target: {value: "otro.log"}});
  fireEvent.click(screen.getByRole("button", {name: "Guardar fuente"}));
  await waitFor(() => expect(api.mock.calls.some(call => call[0] === "/sources/source-1" && call[1] === "PUT")).toBe(true));
  fireEvent.click(screen.getByRole("button", {name: "Cerrar diálogo"}));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.queryByText(/Hay cambios sin guardar/)).toBeNull();
});

it("cerrar el servicio funciona después de agregar una fuente nueva desde el segundo modal", async () => {
  const api = vi.fn(async (path: string, method = "GET") => {
    if (method === "POST" && path === "/services/first/sources") return {};
    if (path === "/services/first") return first;
    if (path.startsWith("/services/first/sources")) return {items: [], total_count: 0};
    return {items: [first], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  await screen.findByText("Fuentes del servicio");
  await pickMenu("Agregar fuente", "Carpeta de logs");
  fireEvent.change(await screen.findByRole("textbox", {name: "Archivo o patrón"}), {target: {value: "access.log"}});
  fireEvent.click(screen.getByRole("button", {name: "Guardar nueva fuente"}));
  await waitFor(() => expect(api.mock.calls.some(call => call[0] === "/services/first/sources" && call[1] === "POST")).toBe(true));
  fireEvent.click(screen.getByRole("button", {name: "Cerrar diálogo"}));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.queryByText(/Hay cambios sin guardar/)).toBeNull();
});

it("incorpora y guarda reglas desde el panel Reglas del servicio, sin abrir el editor de la fuente", async () => {
  let savedRules: unknown = null;
  const baseSource = {id: "source-1", kind: "folder", enabled: true, version: 1, config: {root_alias: "demo-logs", directory: "nginx", selector: "nginx.log"}, analysis: {system: "Nginx", protocol: "HTTP", adapter: "auto", context: "", rules: [] as unknown[]}};
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (method === "PUT" && path === "/sources/source-1") {savedRules = (body as {analysis: {rules: unknown}}).analysis.rules; return {};}
    if (path === "/services/first") return first;
    if (path.startsWith("/services/first/sources")) return {items: [{...baseSource, analysis: {...baseSource.analysis, rules: savedRules || []}}], total_count: 1};
    return {items: [first], total_count: 1};
  });
  render(<ServiceCatalog api={api} />);
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  expect(await screen.findByText(/Reglas: sin reglas incorporadas/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", {name: "Reglas (0)"}));
  fireEvent.change(await screen.findByRole("searchbox", {name: "Buscar reglas para incorporar"}), {target: {value: "acceso"}});
  fireEvent.click(await screen.findByRole("button", {name: /R1: Fallos de acceso/}));
  fireEvent.click(screen.getByRole("button", {name: "Guardar reglas"}));
  await waitFor(() => expect(savedRules).toEqual([{id: "R1", enabled: true, threshold: 5, window_seconds: 60}]));
  expect(await screen.findByText(/Reglas: R1 activa/)).toBeTruthy();
});

it("el panel CVE muestra hallazgos guardados y «Comprobar ahora» consulta el backend", async () => {
  const service = {id: "svc-1", name: "apache-httpd", description: "", context: "", enabled: true, status: "healthy", source_count: 0, version: 2, software_product: "apache:http_server", software_version: "2.4.58", cve_affecting: 1, cve_checked_at: "2026-11-20T12:00:00Z"};
  let checked = false;
  const finding = {id: "f-1", cve_id: "CVE-2024-38474", severity: "critical", base_score: 9.8, summary: "SSRF en Apache HTTP Server.", published: "2024-07-01T00:00:00Z", affects: true, affected_range: "desde 2.4.0, hasta antes de 2.4.60", fixed_version: "2.4.60", refs: ["https://httpd.apache.org/security/vulnerabilities_24.html"]};
  const checkData = {check: {id: "c-1", state: "completed", total_reported: 68, affecting_count: 1, checked_at: "2026-11-20T12:00:00Z"}, findings: [finding]};
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (path.startsWith("/services?")) return {items: [service], total_count: 1};
    if (path === "/services/svc-1") return service;
    if (path.startsWith("/services/svc-1/sources")) return {items: [], total_count: 0, next_cursor: null};
    if (path === "/services/svc-1/cve" && method === "GET") return checked ? checkData : {check: null, findings: []};
    if (path === "/services/svc-1/cve-checks" && method === "POST") {checked = true; return checkData;}
    throw new Error("unexpected " + method + " " + path + " " + JSON.stringify(body));
  });
  render(<ServiceCatalog api={api as never} />);
  expect(await screen.findByText("1 CVE te afectan")).toBeTruthy();
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  expect(await screen.findByText(/Todavía no hay comprobaciones/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", {name: "Comprobar ahora"}));
  expect(await screen.findByText("CVE-2024-38474")).toBeTruthy();
  expect(screen.getByText("Te afecta")).toBeTruthy();
  expect(screen.getByText(/actualizá a 2.4.60 o superior/)).toBeTruthy();
  expect(api.mock.calls.some(([path, method]) => path === "/services/svc-1/cve-checks" && method === "POST")).toBe(true);
});

it("el panel CVE pagina los hallazgos y filtra por afectación", async () => {
  const service = {id: "svc-1", name: "apache-httpd", description: "", context: "", enabled: true, status: "healthy", source_count: 0, version: 2, software_product: "apache:http_server", software_version: "2.4.58"};
  const findings = Array.from({length: 12}, (_, i) => ({id: `f-${i}`, cve_id: `CVE-2024-${1000 + i}`, severity: i % 2 ? "high" : "critical", base_score: 9 - i * 0.1, summary: `Resumen del hallazgo ${i}.`, published: "2024-07-01T00:00:00Z", affects: i < 8, affected_range: "desde 2.4.0, hasta antes de 2.4.60", fixed_version: i < 8 ? "2.4.60" : null, refs: []}));
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (path.startsWith("/services?")) return {items: [service], total_count: 1};
    if (path === "/services/svc-1") return service;
    if (path.startsWith("/services/svc-1/sources")) return {items: [], total_count: 0, next_cursor: null};
    if (path === "/services/svc-1/cve") return {check: {id: "c-1", state: "completed", total_reported: 12, affecting_count: 8, checked_at: "2026-11-20T12:00:00Z"}, findings, history: []};
    throw new Error("unexpected " + method + " " + path + " " + JSON.stringify(body));
  });
  render(<ServiceCatalog api={api as never} />);
  fireEvent.click(await screen.findByRole("button", {name: "Editar"}));
  expect(await screen.findByText("12 hallazgos · Página 1 de 2")).toBeTruthy();
  expect(screen.getByText("CVE-2024-1000")).toBeTruthy();
  expect(screen.queryByText("CVE-2024-1011")).toBeNull();
  fireEvent.click(screen.getByRole("button", {name: "Siguientes"}));
  expect(await screen.findByText("12 hallazgos · Página 2 de 2")).toBeTruthy();
  expect(screen.getByText("CVE-2024-1011")).toBeTruthy();
  fireEvent.click(screen.getByRole("switch", {name: "Solo los que me afectan"}));
  expect(await screen.findByText(/8 te afectan/)).toBeTruthy();
  expect(screen.queryByText("CVE-2024-1011")).toBeNull();
  expect(screen.getAllByText("Te afecta")).toHaveLength(8);
});
it("el laboratorio se conecta desde Agregar servicio, sin botón propio en el encabezado", async () => {
  const api = vi.fn(async () => {
    return {items: [], total_count: 0};
  });
  render(<ServiceCatalog api={api} />);
  await screen.findByText("Sin servicios");
  expect(screen.queryByRole("button", {name: "Conectar laboratorio"})).toBeNull();
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  expect(await screen.findByRole("textbox", {name: "Nombre del servicio"})).toBeTruthy();
  expect(screen.queryByRole("combobox", {name: "Tipo de fuente"})).toBeNull();
  fireEvent.click(screen.getByRole("button", {name: "MCP"}));
  const endpoint = await screen.findByRole("textbox", {name: "Endpoint MCP"});
  expect(endpoint).toHaveProperty("value", "https://192.168.122.210/mcp");
  expect(screen.getByLabelText(/Credencial MCP/)).toBeTruthy();
  expect(screen.queryByRole("textbox", {name: "Nombre del servicio"})).toBeNull();
  fireEvent.click(screen.getByRole("button", {name: "Carpeta de logs"}));
  expect(await screen.findByRole("textbox", {name: "Nombre del servicio"})).toBeTruthy();
});
it("la conexión MCP exige la CA personalizada antes de probar o conectar", async () => {
  const api = vi.fn(async () => ({items: [], total_count: 0}));
  render(<ServiceCatalog api={api} />);
  await screen.findByText("Sin servicios");
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.click(screen.getByRole("button", {name: "MCP"}));
  await screen.findByRole("textbox", {name: "Endpoint MCP"});
  fireEvent.change(screen.getByLabelText(/Credencial MCP/), {target: {value: "token-del-lab"}});
  const probe = screen.getByRole("button", {name: "Probar conexión"}) as HTMLButtonElement;
  const connect = screen.getByRole("button", {name: "Conectar laboratorio"}) as HTMLButtonElement;
  expect(probe.disabled).toBe(false);
  await pickOption("Certificado CA", "Aportar una CA personalizada");
  expect(probe.disabled).toBe(true);
  expect(connect.disabled).toBe(true);
  fireEvent.change(screen.getByRole("textbox", {name: "Certificado CA (PEM)"}), {target: {value: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}});
  expect(probe.disabled).toBe(false);
  expect(connect.disabled).toBe(false);
});
it("la conexión MCP crea las fuentes con las reglas de detección estándar de cada servicio", async () => {
  const servicePosts: any[] = [];
  const sourcePosts: any[] = [];
  const firstSource: Record<string, any> = {};
  let svcCount = 0;
  const api = vi.fn(async (path: string, method = "GET", body?: any) => {
    if (path === "/services" && method === "POST") { servicePosts.push(body); const id = "svc-" + (++svcCount); firstSource[id] = {id: id + "-s1", version: 1, enabled: false, config: body.source.config, analysis: body.source.analysis}; return {id}; }
    if (path.startsWith("/services?")) return {items: [], total_count: 0};
    const sourcesMatch = path.match(/^\/services\/([^/]+)\/sources/);
    if (sourcesMatch && method === "GET") return {items: [firstSource[sourcesMatch[1]]], total_count: 1};
    if (sourcesMatch && method === "POST") { sourcePosts.push({service: sourcesMatch[1], body}); return {id: sourcesMatch[1] + "-s2", version: 1, enabled: false, config: body.config, analysis: body.analysis}; }
    if (path.endsWith("/check")) return {readable: true};
    if (path.startsWith("/sources/") && method === "PUT") return {};
    return {items: [], total_count: 0};
  });
  render(<ServiceCatalog api={api} />);
  await screen.findByText("Sin servicios");
  fireEvent.click(screen.getByRole("button", {name: "Agregar servicio"}));
  fireEvent.click(screen.getByRole("button", {name: "MCP"}));
  await screen.findByRole("textbox", {name: "Endpoint MCP"});
  fireEvent.change(screen.getByLabelText(/Credencial MCP/), {target: {value: "token-del-lab"}});
  fireEvent.click(screen.getByRole("button", {name: "Conectar laboratorio"}));
  expect(await screen.findByText("Conexión finalizada.")).toBeTruthy();
  const ruleIds = (holder: any) => ((holder.source?.analysis?.rules || holder.analysis?.rules || []) as any[]).map(rule => rule.id);
  const nginx = servicePosts.find(post => post.name === "Nginx laboratorio VM");
  expect(ruleIds(nginx)).toEqual(["R1", "R2", "R3", "request_outside_declared_surface", "encoded_path_traversal", "ambiguous_request_normalization"]);
  expect(nginx.source.analysis.rules[0]).toMatchObject({id: "R1", enabled: true, threshold: 5, window_seconds: 60});
  expect(nginx.context.length).toBeGreaterThan(20);
  const ssh = servicePosts.find(post => post.name === "SSH laboratorio VM");
  expect(ruleIds(ssh)).toEqual(["R1", "R2"]);
  const nodeSecurity = sourcePosts.find(post => post.body.config?.resource_uri === "logs://node/security");
  expect(ruleIds(nodeSecurity.body)).toEqual(["R1", "R2"]);
  const nginxError = sourcePosts.find(post => post.body.config?.resource_uri === "logs://nginx/error");
  expect(ruleIds(nginxError.body)).toEqual(["R3"]);
});
