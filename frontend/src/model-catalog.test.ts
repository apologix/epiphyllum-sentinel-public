// Fichas de modelo: autocompletado desde el catálogo, conversión de tarifas y
// diagnóstico exacto de lo que falta antes de habilitar live.
import { expect, it } from "vitest";
import {
  missingSpecFields,
  modelSuggestions,
  specFieldsFrom,
  specFromFields,
  specIsValid,
  unitsToUsd,
  usdToUnits,
  type ModelCatalog,
  type ModelSpec,
} from "./model-catalog";

const spec: ModelSpec = {
  format: "json_schema",
  output_cap: 4096,
  input_cap: 50000,
  timeout_seconds: 60,
  input_rate_units: 200_000_000,
  output_rate_units: 1_000_000_000,
  verified_at: new Date().toISOString(),
  source_url: "https://developers.openai.com/api/docs/pricing",
  token_bound_method: "utf8_bytes_plus_2048_verified",
  billable_output_bounded: true,
  free_account_verified: false,
};

const catalog: ModelCatalog = {
  as_of: "2026-11-23",
  note: "",
  providers: {
    openai: [{ id: "gpt-6.2-sol", label: "GPT-6.2 Sol", provider: "openai", status: "verified", endpoint: "https://api.openai.com/v1", format: "json_schema", output_parameter: "max_completion_tokens", spec, missing: [] }],
    deepseek: [],
    gemini: [],
    claude: [],
    compatible: [],
  },
};

it("convierte tarifas USD por millón a unidades enteras sin flotantes", () => {
  expect(usdToUnits("2")).toBe(200_000_000);
  expect(usdToUnits("0.30")).toBe(30_000_000);
  expect(usdToUnits("1.23456789")).toBe(123_456_789);
  expect(usdToUnits("1.234567891")).toBeNull();
  expect(unitsToUsd(30_000_000)).toBe("0.3");
  expect(unitsToUsd(200_000_000)).toBe("2");
});

it("una ficha completa no tiene faltantes y el autocompletado conserva los valores", () => {
  expect(missingSpecFields(spec, "openai")).toEqual([]);
  expect(specIsValid(spec, "openai")).toBe(true);
  const fields = specFieldsFrom(spec, "openai");
  expect(fields.input_usd).toBe("2");
  expect(fields.output_usd).toBe("10");
  const roundtrip = specFromFields(fields);
  expect(roundtrip.input_rate_units).toBe(spec.input_rate_units);
  expect(roundtrip.output_rate_units).toBe(spec.output_rate_units);
});

it("señala el campo exacto que falta en lugar de un error genérico", () => {
  const missing = missingSpecFields({ ...spec, output_cap: 0, source_url: "" }, "openai");
  expect(missing).toContain("límite de salida (800–4096 tokens)");
  expect(missing).toContain("fuente oficial HTTPS");
});

it("Claude exige json_schema con strict y una fecha vigente", () => {
  const missing = missingSpecFields(
    { ...spec, format: "json_object", verified_at: "2020-01-01T00:00:00Z" },
    "claude",
  );
  expect(missing).toContain("formato json_schema con strict:true (Claude no acepta json_object)");
  expect(missing).toContain("fecha de verificación (no futura y no mayor a 30 días)");
});

it("cruza el catálogo con los modelos que anuncia /models", () => {
  const options = modelSuggestions(catalog, "openai", ["gpt-6.2-sol", "gpt-6-luna"]);
  expect(options[0]).toMatchObject({ id: "gpt-6.2-sol", known: true });
  expect(options[1]).toMatchObject({ id: "gpt-6-luna", known: false });
});
