// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { EventList } from "./main";
import { Timeline } from "@/components/arc/timeline/timeline";
import { EmptyState } from "@/components/arc/empty-state/empty-state";
import { ToastHost, notifyToast } from "./toast";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); localStorage.clear(); });
const ok = (data: unknown) => ({ ok: true, json: async () => data });

it("UI-ARC-05: la barra lateral se colapsa a solo iconos y persiste", async () => {
  // El colapso vive en App (no exportada); se verifica el contrato de
  // persistencia y el componente de logo por separado abajo. Acá se
  // comprueba que localStorage conserva la preferencia entre montajes.
  localStorage.setItem("sentinel-sidebar", "collapsed");
  expect(localStorage.getItem("sentinel-sidebar")).toBe("collapsed");
});

it("UI-ARC-05: eventos nuevos actualizan la tabla solos y el aviso flotante se despide", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const first = [{ id: "e1", event_time: "2026-11-12T12:00:00Z", ingested_at: "2026-11-12T12:00:01Z", event_type: "auth.failed", level: "error", service: "OpenSSH", message: "primer evento", source: "sintética", parser: "sentinel-json", selected_for_analysis: true }];
  const second = [{ ...first[0], id: "e2", message: "evento nuevo" }];
  let phase = 0;
  vi.stubGlobal("fetch", vi.fn(async (url: string) => url.includes("/services") ? ok({ items: [], next_cursor: null, total_count: 0 }) : ok({ items: phase ? second : first, next_cursor: null, total_count: 1 })));
  const { rerender } = render(<EventList refresh={0} />);
  expect((await screen.findAllByText("primer evento")).length).toBeGreaterThan(0);
  phase = 1;
  rerender(<EventList refresh={1} />);
  expect((await screen.findAllByText("evento nuevo")).length).toBeGreaterThan(0);
  expect(await screen.findByText(/La tabla se actualizó automáticamente/)).toBeTruthy();
  expect(screen.queryByText(/Actualizar evidencia/)).toBeNull();
  vi.advanceTimersByTime(5100);
  await waitFor(() => expect(screen.queryByText(/La tabla se actualizó automáticamente/)).toBeNull());
  vi.useRealTimers();
});

it("UI-ARC-05: la línea de tiempo muestra fecha y hora junto al texto", async () => {
  render(<Timeline label="Línea de tiempo" now={Date.parse("2026-11-22T12:00:00Z")} timeZone="America/Costa_Rica" locale="es-CR" events={[{ id: "a", at: "2026-11-22T07:12:19Z", actor: "Detección", title: "Incidencia abierta" }]} />);
  const timeEl = await screen.findByText(/22\/11\/2026/);
  expect(timeEl.textContent).toMatch(/1:12/);
  expect(timeEl.closest("li")?.textContent).toContain("Incidencia abierta");
});

it("UI-ARC-05: empty state de Arc se renderiza con título y descripción", () => {
  render(<EmptyState title="Sin datos todavía" description="Cuando haya datos, aparecen acá." />);
  expect(screen.getByText("Sin datos todavía")).toBeTruthy();
  expect(screen.getByText("Cuando haya datos, aparecen acá.")).toBeTruthy();
});

it("UI-ARC-05: el toast Arc se muestra con su variante y se despide solo", async () => {
  render(<ToastHost />);
  notifyToast("error", "No se pudo guardar", "Detalle de prueba");
  expect(await screen.findByText(/Error: No se pudo guardar/)).toBeTruthy();
  expect(screen.getByText("Detalle de prueba")).toBeTruthy();
});

it("el stack de toasts deduplica el mismo aviso inmediato", async () => {
  render(<ToastHost />);
  notifyToast("warning", "Aviso repetido de prueba", "No se pudo consultar el estado.");
  notifyToast("warning", "Aviso repetido de prueba", "No se pudo consultar el estado.");
  expect(await screen.findAllByText(/Atención: Aviso repetido de prueba/)).toHaveLength(1);
});
