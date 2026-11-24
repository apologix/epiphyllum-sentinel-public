// UI-ARC-08: ventana ACTIVA del Streamgraph del dashboard.
//
// UI-ARC-06 pasó la serie a 24 cubetas por hora cuando las incidencias
// caían en un día, pero las 13 incidencias reales de Allan ocurrieron
// entre 01:12 y 01:38: una sola cubeta con datos y el Streamgraph real
// de Arc dibujaba una espiga en x≈1/24 del ancho (ancho útil medido en
// navegador: 7,5 %). La serie ahora se construye sobre la ventana con
// actividad, no sobre el día completo:
// - ventana = [primera, última] incidencia ± máx(10 min, 15 % de la
//   duración) por lado, alineada a la cubeta;
// - granularidad por duración de la ventana: < 2 h → cubetas de 5 min;
//   < 48 h → cubetas de 1 h; si no → cubetas de 1 día (como antes);
// - si tras agrupar el flujo ocupa < 60 % del ancho (cubetas con datos
//   demasiado juntas), se suaviza cada capa con media móvil de 3
//   cubetas (hasta 2 pasadas, preserva la suma) para que se lea como
//   stream y no como espiga;
// - el epígrafe declara la ventana real: no es el día entero.
import type { StreamgraphDatum } from "@/components/arc/streamgraph/streamgraph";

const TZ = "America/Costa_Rica";
const MIN = 60000;

export type StreamGranularity = "minutes" | "hours" | "days";
export interface StreamWindow {
  data: StreamgraphDatum[];
  granularity: StreamGranularity;
  /** Epígrafe honesto de la tarjeta: la ventana que se está mostrando. */
  caption: string;
  /** Inicio y fin (epoch ms) de la ventana graficada, con margen. */
  windowStart: number;
  windowEnd: number;
  /** True si se aplicó la media móvil de 3 cubetas. */
  smoothed: boolean;
}

const dayKeyOf = (ms: number) =>
  new Date(ms).toLocaleDateString("en-CA", { timeZone: TZ });
const hm = (ms: number) =>
  new Date(ms).toLocaleTimeString("es-CR", {
    timeZone: TZ,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

/** Media móvil de 3 con bordes repetidos: preserva la suma de la serie. */
function smooth3(values: number[]): number[] {
  return values.map((v, i) => {
    const prev = values[Math.max(0, i - 1)] ?? v;
    const next = values[Math.min(values.length - 1, i + 1)] ?? v;
    return (prev + v + next) / 3;
  });
}

/** Fracción del eje ocupada por cubetas con algún dato (0..1). */
function usefulShare(totals: number[]): number {
  const nz = totals
    .map((v, i) => (v > 0 ? i : -1))
    .filter((i) => i >= 0);
  if (!nz.length || totals.length < 2) return 0;
  return (nz[nz.length - 1]! - nz[0]!) / (totals.length - 1);
}

export function buildStreamWindow(
  items: { opened_at: unknown; severity: unknown }[],
  sevKeys: readonly string[],
): StreamWindow | null {
  const times = items
    .map((r) => ({ t: new Date(String(r.opened_at)).getTime(), severity: String(r.severity) }))
    .filter((r) => Number.isFinite(r.t))
    .sort((a, b) => a.t - b.t);
  if (!times.length) return null;
  const first = times[0]!.t;
  const last = times[times.length - 1]!.t;
  const duration = last - first;
  const granularity: StreamGranularity =
    duration >= 48 * 60 * MIN ? "days" : duration >= 2 * 60 * MIN ? "hours" : "minutes";

  if (granularity === "days") {
    // Cubetas por día local desde el primer hasta el último día con
    // actividad: el mismo comportamiento de UI-ARC-06 cuando los datos
    // sí están repartidos en días.
    const keys: string[] = [];
    for (let cursor = first; dayKeyOf(cursor) <= dayKeyOf(last) && keys.length < 62; cursor += 24 * 60 * MIN) {
      const k = dayKeyOf(cursor);
      if (!keys.includes(k)) keys.push(k);
    }
    if (!keys.includes(dayKeyOf(last))) keys.push(dayKeyOf(last));
    const data = keys.map((key) => {
      const at = times.find((r) => dayKeyOf(r.t) === key)!.t;
      return {
        key,
        label: new Date(at).toLocaleDateString("es-CR", {
          timeZone: TZ,
          weekday: "long",
          day: "numeric",
          month: "long",
        }),
        axisLabel: new Date(at).toLocaleDateString("es-CR", {
          timeZone: TZ,
          weekday: "short",
        }),
        values: Object.fromEntries(
          sevKeys.map((k) => [
            k,
            times.filter((r) => r.severity === k && dayKeyOf(r.t) === key).length,
          ]),
        ),
      };
    });
    const startDay = new Date(`${keys[0]}T00:00:00-06:00`).getTime();
    return {
      data,
      granularity,
      caption: "Por día y severidad",
      windowStart: startDay,
      windowEnd: startDay + keys.length * 24 * 60 * MIN,
      smoothed: false,
    };
  }

  const bucketMs = (granularity === "minutes" ? 5 : 60) * MIN;
  const pad = Math.max(10 * MIN, duration * 0.15);
  let start = Math.floor((first - pad) / bucketMs) * bucketMs;
  let end = Math.ceil((last + pad) / bucketMs) * bucketMs;
  // Ventana mínima de 6 cubetas para que una sola incidencia se lea como
  // un pulso centrado y no como una espiga contra el borde.
  while ((end - start) / bucketMs < 6) {
    start -= bucketMs;
    end += bucketMs;
  }
  const count = Math.round((end - start) / bucketMs);
  const raw: Record<string, number[]> = Object.fromEntries(
    sevKeys.map((k) => [k, new Array<number>(count).fill(0)]),
  );
  for (const r of times) {
    const idx = Math.min(count - 1, Math.max(0, Math.floor((r.t - start) / bucketMs)));
    if (raw[r.severity]) raw[r.severity]![idx]! += 1;
  }
  const totals = () =>
    Array.from({ length: count }, (_, i) =>
      sevKeys.reduce((a, k) => a + (raw[k]?.[i] ?? 0), 0),
    );
  let smoothed = false;
  for (let pass = 0; pass < 2 && usefulShare(totals()) < 0.6; pass++) {
    for (const k of sevKeys) raw[k] = smooth3(raw[k]!);
    smoothed = true;
  }
  const data: StreamgraphDatum[] = Array.from({ length: count }, (_, i) => {
    const at = start + i * bucketMs;
    return {
      key: `${granularity === "minutes" ? "m" : "h"}${at}`,
      label:
        granularity === "minutes"
          ? `${hm(at)} – ${hm(at + bucketMs)}`
          : `${hm(at)} – ${hm(at + bucketMs - MIN)}`,
      // Minutos: etiqueta cada 15 min; horas: todas (el componente
      // adelgaza a ~1 por 72 px contando desde la más reciente).
      axisLabel:
        granularity === "hours" || (at / MIN) % 15 === 0 ? hm(at) : "",
      values: Object.fromEntries(sevKeys.map((k) => [k, raw[k]?.[i] ?? 0])),
    };
  });
  return {
    data,
    granularity,
    caption: `Ventana activa ${hm(start)}–${hm(end)} · por severidad`,
    windowStart: start,
    windowEnd: end,
    smoothed,
  };
}
