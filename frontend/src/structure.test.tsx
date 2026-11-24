// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { StructurePanel } from "./services";

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  HTMLDialogElement.prototype.showModal = function () {this.setAttribute("open", "");};
  HTMLDialogElement.prototype.close = function () {this.removeAttribute("open");};
});
afterEach(() => {cleanup(); vi.restoreAllMocks();});

it("el mapa de estructura muestra el diff contra la captura anterior y captura de nuevo", async () => {
  const service = {id: "svc-1", name: "apache-web", enabled: true};
  const overview = {
    roots: [{
      id: "snap-2", root_alias: "demo-logs", directory: "www", node_count: 4, truncated: false,
      created_at: "2026-11-21T12:00:00Z",
      nodes: [
        {path: "index.php", kind: "file", size: 120, mtime: 200, mode: "0644"},
        {path: "uploads", kind: "dir", size: null, mtime: 200, mode: "0755"},
        {path: "uploads/shell.php", kind: "file", size: 44, mtime: 200, mode: "0644"},
        {path: "viejo.txt", kind: "file", size: 9, mtime: 200, mode: "0644"},
      ],
      diff: {
        added: [{path: "uploads/shell.php", kind: "file"}],
        removed: [{path: "tmp.log"}],
        changed: [{path: "index.php", kind: "file", from: {size: 100, mtime: 100, mode: "0644"}, to: {size: 120, mtime: 200, mode: "0644"}}],
      },
    }],
    history: [
      {id: "snap-2", root_alias: "demo-logs", directory: "www", node_count: 4, truncated: false, created_at: "2026-11-21T12:00:00Z"},
      {id: "snap-1", root_alias: "demo-logs", directory: "www", node_count: 3, truncated: false, created_at: "2026-11-21T11:00:00Z"},
    ],
  };
  let captured: unknown = null;
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (path === "/services/svc-1/structure/captures" && method === "POST") {captured = body; return {id: "snap-3"};}
    if (path === "/services/svc-1/structure") return overview;
    throw new Error("unexpected " + method + " " + path);
  });
  render(<StructurePanel api={api as never} service={service} />);
  expect(await screen.findByText(/nunca abre un archivo/)).toBeTruthy();
  expect(await screen.findByText("Rutas nuevas (1)")).toBeTruthy();
  expect(screen.getAllByText("uploads/shell.php").length).toBeGreaterThan(0);
  expect(screen.getByText("Rutas que desaparecieron (1)")).toBeTruthy();
  expect(screen.getByText("tmp.log")).toBeTruthy();
  expect(screen.getByText("Rutas que cambiaron (1)")).toBeTruthy();
  expect(screen.getByText(/Historial de capturas \(2\)/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Directorio"), {target: {value: "www"}});
  fireEvent.click(screen.getByRole("button", {name: "Capturar mapa"}));
  await screen.findByText("Rutas nuevas (1)");
  expect(captured).toEqual({root_alias: "demo-logs", directory: "www"});
});
