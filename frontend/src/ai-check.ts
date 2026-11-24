// Ajustes → «Probar conexión»: presentación del diagnóstico que devuelve
// POST /settings/ai/check. La prueba hace un único GET /models contra el
// proveedor: no genera contenido ni consume tokens.
export interface OpenCodeModelDetail {
  id: string;
  name: string;
  status: "verified" | "pending" | "unsupported";
  compatible: boolean;
  reason: string | null;
  context: number | null;
  output: number | null;
  input_usd: number | null;
  output_usd: number | null;
  structured_output: boolean;
}

export interface AiCheckResult {
  ok: boolean;
  code: string;
  status?: number;
  provider: string;
  model: string;
  latency_ms: number;
  models?: string[] | null;
  model_found?: boolean | null;
  model_details?: {
    endpoint: string;
    excluded: number;
    models: OpenCodeModelDetail[];
  } | null;
}

export interface AiCheckView {
  tone: "ok" | "warn" | "error";
  badgeClass: string;
  badgeText: string;
  title: string;
  detail: string;
}

const PROVIDER_NAMES: Record<string, string> = {
  openai: "OpenAI",
  deepseek: "DeepSeek",
  gemini: "Gemini",
  claude: "Claude / Anthropic",
  opencode: "OpenCode Console",
  compatible: "El proveedor",
};

export function aiCheckView(r: AiCheckResult): AiCheckView {
  const name = PROVIDER_NAMES[r.provider] ?? "El proveedor";
  if (r.ok && !r.model) {
    return {
      tone: "ok",
      badgeClass: "succeeded",
      badgeText: "Credencial aceptada",
      title: `${name} respondió en ${r.latency_ms} ms`,
      detail:
        "La clave fue aceptada y el listado de modelos de la cuenta está disponible. Esto solo comprueba el listado: no genera contenido, no valida la ficha ni autoriza gasto. Elegí un modelo para continuar.",
    };
  }
  if (r.ok && r.model_found === false) {
    const offered = (r.models ?? []).slice(0, 6).join(", ");
    return {
      tone: "warn",
      badgeClass: "medium",
      badgeText: "Revisar modelo",
      title: "La clave funciona, pero el modelo no aparece en la cuenta",
      detail: offered
        ? `${name} aceptó la clave, pero «${r.model}» no está entre los modelos disponibles (${offered}${(r.models ?? []).length > 6 ? ", …" : ""}). Esto solo comprueba el listado; la ficha se valida por separado.`
        : `${name} aceptó la clave, pero «${r.model}» no está entre los modelos disponibles. Revisá el ID o elegí otro de la lista.`,
    };
  }
  if (r.ok) {
    return {
      tone: "ok",
      badgeClass: "succeeded",
      badgeText: "Credencial aceptada",
      title: `${name} respondió en ${r.latency_ms} ms`,
      detail:
        r.model_found === true
          ? `La clave fue aceptada y el modelo «${r.model}» aparece en el listado de la cuenta (${(r.models ?? []).length} modelos). Falta validar la ficha y guardar el perfil; probar la conexión no genera contenido ni consume tokens.`
          : "La clave fue aceptada. El proveedor no devolvió la lista de modelos, así que el modelo no pudo confirmarse con /models.",
    };
  }
  switch (r.code) {
    case "missing_key":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Sin clave",
        title: "No hay una clave para probar",
        detail:
          "Pegue la API key en el campo de clave y vuelva a probar; si ya guardó una, este perfil quedó sin credencial almacenada.",
      };
    case "key_rejected":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Clave rechazada",
        title: `${name} rechazó la credencial (HTTP ${r.status ?? 401})`,
        detail:
          "Revise la API key: puede estar revocada, mal copiada o pertenecer a otro proveedor. Si la escribió ahora, la prueba usa exactamente ese valor.",
      };
    case "access_denied":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Acceso restringido",
        title: `${name} rechazó el acceso (HTTP ${r.status ?? 403})`,
        detail:
          "La clave es válida, pero no tiene permiso para listar o solicitar modelos. Revisá los permisos de la API key en OpenCode Console (Models › Read o Request) o si el modelo está restringido para tu workspace.",
      };
    case "insufficient_balance":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Saldo insuficiente",
        title: `${name} informó un problema de saldo (HTTP ${r.status ?? 402})`,
        detail:
          "La cuenta no tiene crédito suficiente para esta solicitud. Cargá saldo en OpenCode Console o elegí un modelo cubierto por tu plan; Sentinel no cambia de proveedor automáticamente.",
      };
    case "model_unavailable":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Modelo no disponible",
        title: `${name} no tiene disponible «${r.model || "el modelo"}»`,
        detail:
          "El modelo puede estar retirado o no habilitado para tu workspace. Consultá la lista de modelos y elegí uno vigente antes de guardar el perfil.",
      };
    case "provider_error":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Fallo del proveedor",
        title: `${name} devolvió HTTP ${r.status ?? "5xx"}`,
        detail:
          "El proveedor no pudo completar la solicitud. Revisá su estado y volvé a probar más tarde; no se reintenta automáticamente para evitar cargos duplicados.",
      };
    case "rate_limited":
      return {
        tone: "warn",
        badgeClass: "medium",
        badgeText: "Límite alcanzado",
        title: `${name} devolvió 429 (demasiadas solicitudes)`,
        detail:
          "La clave llegó al proveedor, pero la cuenta está limitada en este momento. Espere unos minutos y vuelva a probar.",
      };
    case "destination_denied":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Destino no permitido",
        title: "La Base URL no es un destino permitido",
        detail:
          "Use la URL oficial del proveedor (HTTPS, puerto 443). Para «Compatible», el origen debe estar en la lista permitida del backend.",
      };
    case "unreachable":
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Sin conexión",
        title: `No se pudo contactar a ${name}`,
        detail:
          "El backend no obtuvo respuesta del proveedor. Revise la conexión a Internet del equipo y la Base URL, y vuelva a probar.",
      };
    default:
      return {
        tone: "error",
        badgeClass: "failed",
        badgeText: "Error del proveedor",
        title: `${name} devolvió HTTP ${r.status ?? "—"}`,
        detail:
          "La solicitud llegó al proveedor pero no pudo completarse. Revise el estado del servicio del proveedor y vuelva a probar.",
      };
  }
}

/// Huella de los valores probados: si el formulario cambia después de una
/// prueba, la UI marca el resultado como desactualizado.
export function aiCheckFingerprint(values: {
  provider: string;
  base_url: string;
  model: string;
  typedKey: boolean;
}): string {
  return JSON.stringify(values);
}
