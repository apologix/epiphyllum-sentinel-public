// Catálogo de fichas de modelo (Ajustes → Proveedor de generación).
// El backend entrega las fichas verificadas; esta capa solo las presenta,
// autocompleta el formulario y dice exactamente qué falta antes de habilitar
// live. /models confirma el listado de la cuenta, no la ficha ni el gasto.

export interface ModelSpec {
  format: string;
  output_cap: number;
  input_cap: number;
  timeout_seconds: number;
  input_rate_units: number;
  output_rate_units: number;
  verified_at: string;
  source_url: string;
  token_bound_method: string;
  billable_output_bounded: boolean;
  free_account_verified: boolean;
}

export interface ModelCatalogEntry {
  id: string;
  label: string;
  provider: string;
  status: "verified" | "pending" | "manual";
  endpoint: string;
  format: string;
  output_parameter: string;
  spec: ModelSpec | null;
  missing: string[];
  notes?: string;
  sources?: Record<string, string>;
}

export interface ModelCatalog {
  as_of: string;
  note: string;
  providers: Record<string, ModelCatalogEntry[]>;
  manual?: { provider: string; note: string };
}

export interface SpecFields {
  format: string;
  output_cap: string;
  input_cap: string;
  timeout_seconds: string;
  input_usd: string;
  output_usd: string;
  verified_at: string;
  source_url: string;
  billable_output_bounded: boolean;
  free_account_verified: boolean;
}

export const TOKEN_BOUND_METHOD = "utf8_bytes_plus_2048_verified";
const PROVIDER_LABELS: Record<string, string> = {
  openai: "OpenAI",
  deepseek: "DeepSeek",
  gemini: "Gemini",
  claude: "Claude / Anthropic",
  compatible: "Compatible",
};

export function providerLabel(provider: string): string {
  return PROVIDER_LABELS[provider] ?? provider;
}

export function defaultBase(provider: string): string {
  return provider === "deepseek"
    ? "https://api.deepseek.com"
    : provider === "gemini"
      ? "https://generativelanguage.googleapis.com/v1beta/openai/"
      : provider === "claude"
        ? "https://api.anthropic.com/v1"
        : "https://api.openai.com/v1";
}

export function entriesFor(catalog: ModelCatalog | null | undefined, provider: string): ModelCatalogEntry[] {
  return catalog?.providers?.[provider] ?? [];
}

export function findCatalogEntry(
  catalog: ModelCatalog | null | undefined,
  provider: string,
  id: string,
): ModelCatalogEntry | undefined {
  return entriesFor(catalog, provider).find((entry) => entry.id === id);
}

export function unitsToUsd(units: number | undefined): string {
  if (!Number.isFinite(units) || !units || units < 0) return "";
  const whole = Math.floor(units / 100_000_000);
  const fraction = String(Math.round(units % 100_000_000)).padStart(8, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : String(whole);
}

export function usdToUnits(value: string): number | null {
  const text = value.trim();
  if (!/^\d+(\.\d{1,8})?$/.test(text)) return null;
  const [whole, fraction = ""] = text.split(".");
  const amount = Number(whole) * 100_000_000 + Number(fraction.padEnd(8, "0"));
  return Number.isSafeInteger(amount) ? amount : null;
}

export function emptySpecFields(provider = "compatible"): SpecFields {
  return {
    format: ["openai", "gemini", "claude"].includes(provider) ? "json_schema" : "json_object",
    output_cap: "4096",
    input_cap: "50000",
    timeout_seconds: "60",
    input_usd: "",
    output_usd: "",
    verified_at: new Date().toISOString().slice(0, 10),
    source_url: "",
    billable_output_bounded: false,
    free_account_verified: false,
  };
}

export function specFieldsFrom(spec: Partial<ModelSpec> | null | undefined, provider: string): SpecFields {
  if (!spec) return emptySpecFields(provider);
  const date = typeof spec.verified_at === "string" ? spec.verified_at.slice(0, 10) : "";
  return {
    format: spec.format || (["openai", "gemini", "claude"].includes(provider) ? "json_schema" : "json_object"),
    output_cap: spec.output_cap == null ? "" : String(spec.output_cap),
    input_cap: spec.input_cap == null ? "" : String(spec.input_cap),
    timeout_seconds: spec.timeout_seconds == null ? "" : String(spec.timeout_seconds),
    input_usd: unitsToUsd(spec.input_rate_units),
    output_usd: unitsToUsd(spec.output_rate_units),
    verified_at: date,
    source_url: spec.source_url || "",
    billable_output_bounded: !!spec.billable_output_bounded,
    free_account_verified: !!spec.free_account_verified,
  };
}

export function specFromFields(fields: SpecFields): ModelSpec {
  const input = usdToUnits(fields.input_usd);
  const output = usdToUnits(fields.output_usd);
  const date = fields.verified_at.trim();
  return {
    format: fields.format,
    output_cap: Number(fields.output_cap),
    input_cap: Number(fields.input_cap),
    timeout_seconds: Number(fields.timeout_seconds),
    input_rate_units: input ?? 0,
    output_rate_units: output ?? 0,
    verified_at: date ? `${date.slice(0, 10)}T00:00:00Z` : "",
    source_url: fields.source_url.trim(),
    token_bound_method: TOKEN_BOUND_METHOD,
    billable_output_bounded: fields.billable_output_bounded,
    free_account_verified: fields.free_account_verified,
  };
}

export function missingSpecFields(spec: Partial<ModelSpec> | null | undefined, provider: string): string[] {
  const missing: string[] = [];
  if (!spec) return ["ficha del modelo"];
  if (!["json_object", "json_schema"].includes(spec.format ?? "")) {
    missing.push("formato estructurado (json_object o json_schema)");
  }
  if (provider === "claude" && spec.format !== "json_schema") {
    missing.push("formato json_schema con strict:true (Claude no acepta json_object)");
  }
  const integer = (value: unknown) => typeof value === "number" && Number.isInteger(value);
  if (!integer(spec.output_cap) || spec.output_cap! < 800 || spec.output_cap! > 4096) {
    missing.push("límite de salida (800–4096 tokens)");
  }
  if (!integer(spec.input_cap) || spec.input_cap! < 4096 || spec.input_cap! > 100000) {
    missing.push("límite de entrada (4096–100000 tokens)");
  }
  if (!integer(spec.timeout_seconds) || spec.timeout_seconds! < 1 || spec.timeout_seconds! > 60) {
    missing.push("tiempo máximo (1–60 segundos)");
  }
  if (!spec.billable_output_bounded) {
    missing.push("cota de salida facturable confirmada");
  }
  if (spec.token_bound_method !== TOKEN_BOUND_METHOD) {
    missing.push("método de cota UTF-8 + 2048 verificado");
  }
  const verified = typeof spec.verified_at === "string" ? Date.parse(spec.verified_at) : NaN;
  const age = Date.now() - verified;
  if (!Number.isFinite(verified) || age < 0 || age > 30 * 24 * 60 * 60 * 1000) {
    missing.push("fecha de verificación (no futura y no mayor a 30 días)");
  }
  let source: URL | null = null;
  try {
    source = new URL(spec.source_url ?? "");
  } catch {
    source = null;
  }
  if (!source || source.protocol !== "https:" || !source.hostname) {
    missing.push("fuente oficial HTTPS");
  }
  const input = spec.input_rate_units ?? 0;
  const output = spec.output_rate_units ?? 0;
  const bounded = Number.isInteger(input) && Number.isInteger(output) && input <= 100_000_000_000 && output <= 100_000_000_000;
  if (!bounded || (!spec.free_account_verified && (input <= 0 || output <= 0))) {
    missing.push("tarifa de entrada y salida (o gratuidad verificada por el operador)");
  }
  return [...new Set(missing)];
}

export function specIsValid(spec: Partial<ModelSpec> | null | undefined, provider: string): boolean {
  return missingSpecFields(spec, provider).length === 0;
}

export function modelSuggestions(
  catalog: ModelCatalog | null | undefined,
  provider: string,
  advertised: string[] | null | undefined,
): { id: string; label: string; known: boolean }[] {
  const seen = new Set<string>();
  const options: { id: string; label: string; known: boolean }[] = [];
  for (const entry of entriesFor(catalog, provider)) {
    if (seen.has(entry.id)) continue;
    seen.add(entry.id);
    options.push({ id: entry.id, label: `${entry.label} (${entry.id})`, known: true });
  }
  for (const id of advertised ?? []) {
    if (seen.has(id)) continue;
    seen.add(id);
    options.push({ id, label: `${id} (disponible en la cuenta)`, known: false });
  }
  return options;
}
