// UI-ARC-08: la ventana activa del Streamgraph. Las marcas de Allan son
// las reales de su stack: 13 incidencias HOY entre 01:12 y 01:38 (hora
// de Costa Rica, -06:00) — 1 crítica, 3 altas, 5 medias, 4 bajas. Con la
// serie de UI-ARC-06 (24 cubetas horarias) ocupaban UNA cubeta y el
// flujo medía 7,5 % del ancho del gráfico.
import { expect, it } from "vitest";
import { buildStreamWindow } from "./stream-window";

const SEV = ["critical", "high", "medium", "low"] as const;
const at = (hhmmss: string, day = "2026-11-22") => `${day}T${hhmmss}-06:00`;
const item = (opened_at: string, severity: string) => ({ opened_at, severity });
const totalOf = (w: NonNullable<ReturnType<typeof buildStreamWindow>>) =>
  w.data.reduce((a, d) => a + SEV.reduce((x, k) => x + (d.values[k] ?? 0), 0), 0);
const usefulShare = (w: NonNullable<ReturnType<typeof buildStreamWindow>>) => {
  const totals = w.data.map((d) => SEV.reduce((a, k) => a + (d.values[k] ?? 0), 0));
  const nz = totals.map((v, i) => (v > 0 ? i : -1)).filter((i) => i >= 0);
  return (nz[nz.length - 1]! - nz[0]!) / (totals.length - 1);
};

const allan = [
  ["01:12:19", "low"], ["01:12:19", "medium"], ["01:13:05", "high"], ["01:16:40", "medium"],
  ["01:19:22", "low"], ["01:21:03", "medium"], ["01:25:47", "critical"], ["01:28:31", "high"],
  ["01:31:12", "medium"], ["01:33:55", "low"], ["01:35:20", "medium"], ["01:36:44", "high"],
  ["01:37:58", "low"],
].map(([t, s]) => item(at(t), s));

it("UI-ARC-08: concentrado (26 min) → ventana en minutos que cubre la actividad", () => {
  const w = buildStreamWindow(allan, SEV)!;
  expect(w).not.toBeNull();
  expect(w.granularity).toBe("minutes");
  // La ventana nace de los datos (01:12–01:38 ± margen), no del día:
  // empieza antes de 01:12 y termina después de 01:38, sin llegar a 1 h.
  expect(w.windowStart).toBeLessThan(new Date(at("01:12:19")).getTime());
  expect(w.windowEnd).toBeGreaterThan(new Date(at("01:37:58")).getTime());
  expect(w.windowEnd - w.windowStart).toBeLessThan(60 * 60000);
  // Epígrafe honesto con horas:minutos reales de la ventana.
  expect(w.caption).toMatch(/^Ventana activa 01:\d{2}–01:\d{2} · por severidad$/);
  // El eje etiqueta en cuartos de hora reales (01:00, 01:15, 01:30…).
  const axis = w.data.map((d) => d.axisLabel).filter(Boolean);
  expect(axis.length).toBeGreaterThanOrEqual(3);
  expect(axis.every((a) => /^01:(00|15|30|45)$/.test(a!))).toBe(true);
  // Objetivo de la ronda: el flujo ocupa ≥ 70 % del ancho en cubetas.
  expect(usefulShare(w)).toBeGreaterThanOrEqual(0.7);
  // Nada se pierde: la suma por severidad se conserva (13 incidencias).
  expect(totalOf(w)).toBeCloseTo(13, 5);
});

it("UI-ARC-08: varias horas el mismo día → ventana por horas del rango activo", () => {
  const items = [
    ["09:05:00", "medium"], ["09:40:00", "low"], ["10:15:00", "high"], ["11:30:00", "medium"],
    ["12:45:00", "low"], ["13:20:00", "medium"], ["14:10:00", "high"], ["15:35:00", "low"],
    ["16:05:00", "medium"], ["16:50:00", "critical"],
  ].map(([t, s]) => item(at(t), s));
  const w = buildStreamWindow(items, SEV)!;
  expect(w.granularity).toBe("hours");
  // No es 0–23: la ventana rodea 09–17, con margen, sin abrir el día.
  const startH = new Date(w.windowStart).toLocaleTimeString("es-CR", { timeZone: "America/Costa_Rica", hour: "2-digit", hour12: false });
  const endH = new Date(w.windowEnd).toLocaleTimeString("es-CR", { timeZone: "America/Costa_Rica", hour: "2-digit", hour12: false });
  expect(Number(startH)).toBeGreaterThanOrEqual(6);
  expect(Number(startH)).toBeLessThanOrEqual(9);
  expect(Number(endH)).toBeGreaterThanOrEqual(17);
  expect(Number(endH)).toBeLessThanOrEqual(19);
  expect(w.caption).toMatch(/^Ventana activa \d{2}:00–\d{2}:00 · por severidad$/);
  expect(totalOf(w)).toBeCloseTo(10, 5);
});

it("UI-ARC-08: repartido en 7 días → cubetas por día, como antes", () => {
  const items = [
    item(at("10:15:00", "2026-11-16"), "medium"), item(at("11:15:00", "2026-11-17"), "low"),
    item(at("09:15:00", "2026-11-18"), "high"), item(at("12:15:00", "2026-11-19"), "medium"),
    item(at("10:15:00", "2026-11-20"), "critical"), item(at("13:15:00", "2026-11-21"), "low"),
    item(at("10:15:00", "2026-11-22"), "medium"),
  ];
  const w = buildStreamWindow(items, SEV)!;
  expect(w.granularity).toBe("days");
  expect(w.data.length).toBe(7);
  expect(w.caption).toBe("Por día y severidad");
  expect(w.smoothed).toBe(false);
  expect(totalOf(w)).toBeCloseTo(7, 5);
});

it("UI-ARC-08: una sola incidencia → ventana mínima legible, sin espiga rota", () => {
  const w = buildStreamWindow([item(at("10:30:00"), "high")], SEV)!;
  expect(w).not.toBeNull();
  expect(w.granularity).toBe("minutes");
  expect(w.data.length).toBeGreaterThanOrEqual(6);
  expect(w.data.every((d) => SEV.every((k) => Number.isFinite(d.values[k] ?? 0)))).toBe(true);
  expect(totalOf(w)).toBeCloseTo(1, 5);
  expect(w.caption).toMatch(/^Ventana activa /);
});

it("UI-ARC-08: sin incidencias → null (la tarjeta usa su estado vacío)", () => {
  expect(buildStreamWindow([], SEV)).toBeNull();
});
