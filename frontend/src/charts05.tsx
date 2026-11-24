// Gráficos del dashboard (UI-ARC-05, corregido en UI-ARC-06).
// UI-ARC-05 los había construido propios porque se creyó que no estaban
// en el registry free de Arc. En UI-ARC-06 Allan mostró las capturas de
// uiarc.dev con el comando de instalación y el registry SÍ respondió:
//   npx shadcn@latest add @uiarc/waffle-chart @uiarc/streamgraph
// instaló los componentes reales en src/components/arc/. Este archivo ya
// no dibuja nada: solo adapta los datos de Sentinel a sus APIs.
// - Streamgraph real: baseline "wiggle" centrada, capas con etiquetas
//   directas y leyenda conmutables, como la captura de referencia.
// - WaffleChart real: grilla 10×10 compacta + leyenda lateral con %,
//   como la captura de referencia.
import { Streamgraph as ArcStreamgraph, type StreamgraphDatum, type StreamgraphSeries } from "@/components/arc/streamgraph/streamgraph";
import { WaffleChart as ArcWaffleChart, type WaffleCategory } from "@/components/arc/waffle-chart/waffle-chart";

export type { StreamgraphDatum, StreamgraphSeries, WaffleCategory };

export function StreamPanel({ data, series, height = 208, categoryLabel = "Día" }: { data: StreamgraphDatum[]; series: StreamgraphSeries[]; height?: number; categoryLabel?: string }) {
  return <ArcStreamgraph data={data} series={series} label="Flujo de incidencias por severidad en la ventana activa" unit="incidencias" height={height} offset="wiggle" categoryLabel={categoryLabel} emptyLabel="Sin flujo para mostrar" />;
}

export function WafflePanel({ data }: { data: WaffleCategory[] }) {
  const total = data.reduce((a, s) => a + Math.max(0, s.value), 0);
  return <ArcWaffleChart data={data} label={`Incidencias por servicio (${total} registradas)`} unit="incidencias" emptyLabel="Sin incidencias por servicio" />;
}

const WAFFLE_COLORS = ["#6ea8fe", "#e8a33d", "#46a758", "#e5484d", "#9e8cfc", "#8b9bab", "#f76b15", "#ffb224"];
export { WAFFLE_COLORS };
