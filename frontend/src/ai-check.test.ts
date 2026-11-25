// «Probar conexión» (Ajustes): el diagnóstico del backend se presenta con
// tono, distintivo y texto accionable según el código devuelto.
import { expect, it } from "vitest";
import { aiCheckFingerprint, aiCheckView, type AiCheckResult } from "./ai-check";

const base: AiCheckResult = {
  ok: true,
  code: "ok",
  status: 200,
  provider: "deepseek",
  model: "deepseek-chat",
  latency_ms: 212,
  models: ["deepseek-chat", "deepseek-reasoner"],
  model_found: true,
};

it("éxito con modelo disponible: tono ok y latencia visible", () => {
  const v = aiCheckView(base);
  expect(v.tone).toBe("ok");
  expect(v.badgeText).toBe("Credencial aceptada");
  expect(v.title).toContain("DeepSeek");
  expect(v.title).toContain("212 ms");
  expect(v.detail).toContain("deepseek-chat");
});

it("sin modelo, la prueba solo confirma el listado de la cuenta", () => {
  const v = aiCheckView({ ...base, model: "", model_found: null });
  expect(v.tone).toBe("ok");
  expect(v.badgeText).toBe("Credencial aceptada");
  expect(v.detail).toContain("listado");
  expect(v.detail).toContain("no valida la ficha");
});

it("clave aceptada pero modelo ausente: aviso con los modelos reales", () => {
  const v = aiCheckView({ ...base, model: "deepseek-chatt", model_found: false });
  expect(v.tone).toBe("warn");
  expect(v.badgeText).toBe("Revisar modelo");
  expect(v.detail).toContain("deepseek-chat, deepseek-reasoner");
});

it("clave rechazada, sin clave y sin conexión dan textos distintos", () => {
  const rejected = aiCheckView({ ...base, ok: false, code: "key_rejected", status: 401 });
  expect(rejected.tone).toBe("error");
  expect(rejected.title).toContain("401");
  const missing = aiCheckView({ ...base, ok: false, code: "missing_key" });
  expect(missing.badgeText).toBe("Sin clave");
  const down = aiCheckView({ ...base, ok: false, code: "unreachable" });
  expect(down.badgeText).toBe("Sin conexión");
});

it("la huella cambia cuando cambia cualquier valor probado", () => {
  const a = aiCheckFingerprint({ provider: "deepseek", base_url: "https://api.deepseek.com", model: "deepseek-chat", typedKey: false });
  const b = aiCheckFingerprint({ provider: "deepseek", base_url: "https://api.deepseek.com", model: "deepseek-reasoner", typedKey: false });
  const c = aiCheckFingerprint({ provider: "deepseek", base_url: "https://api.deepseek.com", model: "deepseek-chat", typedKey: true });
  expect(a).not.toBe(b);
  expect(a).not.toBe(c);
});
