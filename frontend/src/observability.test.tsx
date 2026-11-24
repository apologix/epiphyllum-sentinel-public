// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ClassificationBadge, ObservabilityPanel } from "./observability";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("la insignia de clasificación usa el lenguaje calibrado en español", () => {
  render(<ClassificationBadge value="outside_declared_boundary" />);
  expect(screen.getByText("Fuera de superficie declarada")).toBeTruthy();
});

it("el panel de límites observables lista rutas, crea una entrada y carga el conjunto del laboratorio", async () => {
  const service = {id: "svc-1", name: "nginx-lab", enabled: true};
  const entry = {
    entry_id: "e-1", revision: 2, scope: "http", entry_kind: "route", status: "active",
    description: "Zona autenticada",
    config: {path_pattern: "/secure/", match_kind: "prefix", exposure: "authenticated", allowed_methods: ["GET", "POST"], expected_behavior: ""},
    created_at: "2026-11-21T12:00:00Z",
  };
  let created: unknown = null;
  let seeded = false;
  const api = vi.fn(async (path: string, method = "GET", body?: unknown) => {
    if (path.startsWith("/services/svc-1/observability?")) return {items: [entry], total: 1, fingerprint: "abcdef1234567890"};
    if (path === "/services/svc-1/observability" && method === "POST") { created = body; return {...entry, revision: 1}; }
    if (path === "/services/svc-1/observability-seed-lab" && method === "POST") { seeded = true; return {created: []}; }
    throw new Error("unexpected " + method + " " + path);
  });
  render(<ObservabilityPanel api={api as never} service={service} sources={[]} />);
  expect(await screen.findByText("/secure/")).toBeTruthy();
  expect(screen.getAllByText("Autenticada").length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText("v2")).toBeTruthy();

  fireEvent.click(screen.getByText("Nueva entrada"));
  fireEvent.change(screen.getByPlaceholderText("/files/ o /users/{id}"), {target: {value: "/files/"}});
  fireEvent.change(screen.getByPlaceholderText("GET, HEAD"), {target: {value: "GET, HEAD"}});
  fireEvent.click(screen.getByText("Guardar entrada"));
  await vi.waitFor(() => expect(created).toBeTruthy());
  expect((created as {config: {path_pattern: string}}).config.path_pattern).toBe("/files/");

  fireEvent.mouseDown(screen.getByRole("tab", {name: "Fuentes y limitaciones"}));
  await vi.waitFor(() => expect((screen.getByRole("button", {name: "Cargar conjunto inicial del laboratorio Nginx"}) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", {name: "Cargar conjunto inicial del laboratorio Nginx"}));
  await vi.waitFor(() => expect(seeded).toBe(true));
});
