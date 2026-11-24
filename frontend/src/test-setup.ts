// jsdom no implementa ResizeObserver y los primitivos de Radix que usa Arc
// (Switch, Select, etc.) lo requieren sin guarda. Sustituto mínimo para el
// entorno de pruebas: cumple la interfaz sin observar nada. En el navegador
// real existe el nativo y este archivo no se carga.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver =
    ResizeObserverStub as unknown as typeof ResizeObserver;
}

// jsdom tampoco trae IntersectionObserver y los gráficos de Arc (DonutChart,
// BarChart) y el Timeline lo usan vía motion/useInView sin guarda
// (UI-ARC-05: el tab CVE monta el DonutChart). Sustituto inerte de pruebas.
class IntersectionObserverStub {
  root = null;
  rootMargin = "";
  thresholds: number[] = [];
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return []; }
}
if (typeof globalThis.IntersectionObserver === "undefined") {
  globalThis.IntersectionObserver =
    IntersectionObserverStub as unknown as typeof IntersectionObserver;
}

// jsdom tampoco implementa scrollIntoView ni la captura de puntero que
// Radix Select usa al abrirse. Sustitutos inertes, solo para pruebas.
if (typeof Element !== "undefined") {
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = () => {};
  }
  const proto = Element.prototype as unknown as Record<string, unknown>;
  if (!proto.hasPointerCapture) proto.hasPointerCapture = () => false;
  if (!proto.setPointerCapture) proto.setPointerCapture = () => {};
  if (!proto.releasePointerCapture) proto.releasePointerCapture = () => {};
}

// La VM de pruebas comparte CPU y los componentes con animación (motion)
// tardan más en asentarse bajo carga paralela; las consultas asíncronas
// esperan hasta 3 s la misma condición (sin cambiar ninguna aserción).
import { configure } from "@testing-library/react";
configure({ asyncUtilTimeout: 3000 });
