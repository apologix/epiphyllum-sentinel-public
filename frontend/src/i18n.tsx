import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type Lang = "es" | "en";

const STORAGE_KEY = "sentinel.lang";
let activeLocale = "es-CR";

export function locale(): string {
  return activeLocale;
}

export function pickLang(input: { search?: string; stored?: string | null; languages?: readonly string[] }): Lang {
  const query = new URLSearchParams(input.search ?? "").get("lang");
  if (query === "es" || query === "en") return query;
  if (input.stored === "es" || input.stored === "en") return input.stored;
  const first = input.languages?.[0] ?? "";
  // Spanish gets Spanish; every other browser language falls back to English.
  return /^es\b/i.test(first) ? "es" : "en";
}

const EN: Record<string, string> = {
  // Shell
  "Resumen": "Summary",
  "Incidencias": "Incidents",
  "Eventos": "Events",
  "Conocimiento": "Knowledge",
  "Servicios": "Services",
  "Análisis": "Analysis",
  "Estado y costos": "Status and costs",
  "Ajustes": "Settings",
  "Observación e investigación": "Observation and investigation",
  "Fuentes configuradas por el operador.": "Sources configured by the operator.",
  "Las decisiones las toma una persona.": "Decisions are made by a person.",
  "Cerrar sesión": "Sign out",
  "Expandir barra lateral": "Expand sidebar",
  "Colapsar barra lateral": "Collapse sidebar",
  "Menú": "Menu",
  "Navegación": "Navigation",
  "Navegación principal": "Main navigation",
  "Saltar al contenido": "Skip to content",
  "Investigación local": "Local investigation",
  "Fuentes de laboratorio": "Lab sources",
  "API configurada": "API configured",
  "Sin API": "No API",
  "IA pausada": "AI paused",
  "● Conectado": "● Connected",
  "○ Reconectando": "○ Reconnecting",
  "Comprobando sesión local…": "Checking local session…",
  "Investigar con evidencia": "Investigate with evidence",
  "Aplicación local de laboratorio. Ingrese el secreto administrativo de su archivo .env.": "Local lab application. Enter the administrative secret from your .env file.",
  "Secreto de acceso": "Access secret",
  "Iniciar sesión": "Sign in",
  "Producto informativo. Sin herramientas ni acciones sobre sistemas.": "Informational product. No tools or actions against systems.",
  // View descriptions
  "Actividad, prioridades y costos de la demo, en un solo lugar.": "Activity, priorities, and demo costs in one place.",
  "Hallazgos de IA y reglas que requieren revisión humana.": "AI findings and rules that need human review.",
  "Cronología de recepción de los registros.": "Record receipt timeline.",
  "Guías y políticas versionadas, con recuperación vectorial.": "Versioned guides and policies with vector retrieval.",
  "Configure el proveedor y revise las tarifas.": "Configure the provider and review rates.",
  "Dependencias y contabilidad persistente.": "Dependencies and persistent accounting.",
  // States
  "Histórico": "Historical",
  "IA externa": "External AI",
  "Local por política": "Local by policy",
  "Original histórico no recuperado": "Historical original not recovered",
  "Mixto histórico": "Historical mixed",
  "En curso": "In progress",
  "No concluyente": "Inconclusive",
  "Bloqueado": "Blocked",
  "Pendiente": "Pending",
  "Recuperando fuentes": "Retrieving sources",
  "Reservado": "Reserved",
  "Generando": "Generating",
  "Completado": "Completed",
  "Caché": "Cache",
  "Presupuesto agotado": "Budget exhausted",
  "Envío ambiguo, sin reenvío": "Ambiguous send, not retried",
  "Falló el proveedor": "Provider failed",
  "Detenido por el operador": "Stopped by operator",
  "Indexando": "Indexing",
  "Lista": "Ready",
  "Borrador": "Draft",
  // Severity
  "Crítica": "Critical",
  "Alta": "High",
  "Media": "Medium",
  "Baja": "Low",
  "Informativa": "Informational",
  // Review reasons
  "Los registros de esta incidencia todavía no están asignados a un servicio.": "This incident's records are not assigned to a service yet.",
  "Generación pausada por el operador; no se envían solicitudes externas.": "Generation paused by the operator; no external requests are sent.",
  "Configure un proveedor y autorice el lote para generar análisis nuevos.": "Configure a provider and authorize the batch to generate new analyses.",
  "Falta la credencial del perfil fijado.": "The pinned profile credential is missing.",
  "Faltan capacidades, tarifa o límites verificados.": "Verified capabilities, rates, or limits are missing.",
  "Trabajo bloqueado por una configuración anterior; revise su estado antes de repetirlo.": "Job blocked by a previous configuration; review its state before retrying.",
  "El saldo no alcanza para reservar el bloque completo.": "The balance cannot cover the full reservation.",
  "Se alcanzó el límite monetario de la sesión; ajustalo en Ajustes para nuevas solicitudes.": "The session spend limit was reached; adjust it in Settings for new requests.",
  "La política de revisión primaria denegó el envío.": "The primary review policy denied the send.",
  "El envío externo quedó ambiguo; no se reenvía automáticamente.": "The external send is ambiguous; it is not retried automatically.",
  "Respuesta parcial: se conservaron los resultados válidos y faltan segmentos.": "Partial response: valid results were kept and some segments are missing.",
  "Texto hostil: permanece local por política.": "Hostile text: kept local by policy.",
  "Texto sensible: permanece local por política.": "Sensitive text: kept local by policy.",
  "La entrada no es texto UTF8 válido.": "Input is not valid UTF-8 text.",
  "Supera 1 MiB: se conserva referencia verificable, sin revisión IA.": "Exceeds 1 MiB: a verifiable reference is kept, without AI review.",
  "El original histórico todavía no pudo recuperarse.": "The historical original could not be recovered yet.",
  "Detenido por el operador; no se enviará.": "Stopped by the operator; it will not be sent.",
  "Pausa temporal: tres respuestas fallidas o ambiguas seguidas.": "Temporary pause: three failed or ambiguous responses in a row.",
  "La API respondió, pero la respuesta no cumplió el contrato.": "The API responded, but the response did not satisfy the contract.",
  // Common actions and labels
  "Anterior": "Previous",
  "Siguiente": "Next",
  "Volver": "Back",
  "Guardar": "Save",
  "Guardar borrador": "Save draft",
  "Guardar y habilitar": "Save and enable",
  "Cancelar": "Cancel",
  "Cerrar": "Close",
  "Editar": "Edit",
  "Quitar": "Remove",
  "Activar": "Enable",
  "Desactivar": "Disable",
  "Probar conexión": "Test connection",
  "Probando…": "Testing…",
  "Actualizar": "Refresh",
  "Reintentar": "Retry",
  "Ver contenido": "View content",
  "Buscar": "Search",
  "Todos": "All",
  "Página": "Page",
  "Por página": "Per page",
  "por página": "per page",
  "Estado": "Status",
  "Servicio": "Service",
  "Severidad": "Severity",
  "Regla": "Rule",
  "Acciones": "Actions",
  "Detalle": "Detail",
  "Contenido": "Content",
  "Fuente": "Source",
  "Origen": "Origin",
  "Modelo": "Model",
  "Proveedor": "Provider",
  "Fecha": "Date",
  "Total": "Total",
  "Sin datos": "No data",
  "Sin registros": "No records",
  "No hay fuentes configuradas": "No sources configured",
  "Fuentes configuradas": "Configured sources",
  "Tabla de fuentes configuradas": "Configured sources table",
  "Tabla de reglas empresariales": "Business rules table",
  "Reglas empresariales locales": "Local business rules",
  "Agregar o editar una regla": "Add or edit a rule",
  "Guardar regla": "Save rule",
  "Servicio de regla": "Rule service",
  "Umbral": "Threshold",
  "Ventana (s)": "Window (s)",
  "Habilitada": "Enabled",
  "Deshabilitada": "Disabled",
  "Todos los servicios": "All services",
  "Recepción": "Received",
  "Recibido": "Received",
  "Diagnósticos": "Diagnostics",
  "Último error": "Last error",
  "Bytes pendientes": "Pending bytes",
  "Segmentos": "Segments",
  "Contenido temporal expirado": "Temporary content expired",
  "Sin parser": "No parser",
  "pendiente": "pending",
  "sin respuesta": "no response",
  "Registros preservados": "Preserved records",
  "Alcance y costo pendiente": "Scope and pending cost",
  "Contenido redactado y segmentos": "Redacted content and segments",
  "Hash original": "Original hash",
  "Segmento": "Segment",
  "Cerrar contenido": "Close content",
  "La cobertura cuenta disposiciones validadas; no garantiza detectar todas las amenazas.": "Coverage counts validated dispositions; it does not guarantee detecting every threat.",
  // Settings core
  "Proveedor de generación": "Generation provider",
  "Límite de gasto de la sesión": "Session spend limit",
  "Detector de CVE": "CVE detector",
  "API key de escritura única": "Write-only API key",
  "Nombre del perfil": "Profile name",
  "Base URL HTTPS": "Base URL HTTPS",
  "Ficha técnica y opciones avanzadas": "Technical spec and advanced options",
  "Formato estructurado": "Structured format",
  "Límite de salida (tokens)": "Output limit (tokens)",
  "Límite de entrada (tokens)": "Input limit (tokens)",
  "Tiempo máximo (segundos)": "Timeout (seconds)",
  "Tarifa de entrada (USD por millón)": "Input rate (USD per million)",
  "Tarifa de salida (USD por millón)": "Output rate (USD per million)",
  "Fecha de verificación": "Verification date",
  "Fuente oficial (HTTPS)": "Official source (HTTPS)",
  "Modelo profundo (opcional)": "Deep model (optional)",
  "Usar el modelo estándar": "Use the standard model",
  "Credencial: guardada": "Credential: stored",
  "Credencial: sin guardar": "Credential: not stored",
  "Clave lista": "Key ready",
  "Falta la clave": "Missing key",
  "Ficha lista": "Spec ready",
  "Ficha incompleta": "Incomplete spec",
  "Sin modelo": "No model",
  "Modelo comprobado en /models": "Model found in /models",
  "Modelo sin comprobar": "Model not checked",
  "Configurar": "Configure",
  "Configuración activa": "Active configuration",
  // Notifications and dashboard
  "Cerrar aviso": "Dismiss notice",
  "Notificaciones": "Notifications",
  "Marcar todas como leídas": "Mark all as read",
  "No hay notificaciones": "No notifications",
  "Cuando una incidencia nueva requiera revisión, aparece acá.": "When a new incident needs review, it appears here.",
  "Leída": "Read",
  "Sin leer": "Unread",
  "Servicio sin identificar": "Unidentified service",
  "Detección disponible": "Detection available",
  "Se muestran las 100 notificaciones más recientes.": "Showing the 100 most recent notifications.",
  "Fallos de autenticación": "Authentication failures",
  "Accesos exitosos": "Successful logins",
  "Errores de aplicación": "Application errors",
  "Avisos del sistema": "System notices",
  "Cargando métricas de la demo…": "Loading demo metrics…",
  "Notas guardadas.": "Notes saved.",
  "Notas guardadas": "Notes saved",
  "No se pudieron guardar las notas": "Could not save notes",
  "No se pudieron marcar las notificaciones": "Could not mark notifications",
  "No se pudo abrir la notificación": "Could not open the notification",
  "Notificaciones marcadas como leídas": "Notifications marked as read",
  "Revisión de registros y cobertura": "Record review and coverage",
  "Reglas empresariales": "Business rules",
  "No se pudo completar la solicitud.": "The request could not be completed.",
  "No se pudo guardar el borrador": "Could not save the draft",
  "No se pudo guardar el límite de gasto": "Could not save the spend limit",
  "No se pudo guardar el detector de CVE": "Could not save the CVE detector",
  "Perfil guardado y habilitado": "Profile saved and enabled",
  "Borrador guardado": "Draft saved",
  "Límite de gasto activado": "Spend limit enabled",
  "Límite de gasto desactivado": "Spend limit disabled",
  "Detector de CVE actualizado": "CVE detector updated",
  "Modelo no compatible": "Unsupported model",
  "Ficha del modelo incompleta": "Incomplete model spec",
  "Ficha del modelo profundo incompleta": "Incomplete deep model spec",
  "No se pudo probar la conexión": "Could not test the connection",
  "Reglas actualizadas": "Rules updated",
  "No se pudieron guardar las reglas": "Could not save the rules",
  "Regla guardada. No altera la cobertura IA ni cambia la configuración de la API.": "Rule saved. It does not change AI coverage or the API configuration.",
  "Todavía no hay reglas empresariales: agregá la primera con el formulario de abajo.": "There are no business rules yet: add the first one with the form below.",
  "Páginas de reglas empresariales": "Business rules pages",
  "Páginas de registros": "Record pages",
  "Páginas de eventos": "Event pages",
  "Páginas de conocimiento": "Knowledge pages",
  "Páginas de versiones del corpus": "Corpus version pages",
  "Paginación de incidencias": "Incident pagination",
  "Lista de notificaciones": "Notification list",
  "Contenido del registro": "Record content",
};

const PATTERNS: Array<[RegExp, (m: RegExpMatchArray) => string]> = [
  [/^Investigación local \/ (.+)$/, (m) => `Local investigation / ${translateText(m[1], "en")}`],
  [/^Página (\d+) de (\d+)$/, (m) => `Page ${m[1]} of ${m[2]}`],
  [/^Página (\d+)$/, (m) => `Page ${m[1]}`],
  [/^(\d+) eventos · Página (\d+) · ordenados por recepción, del más reciente al más antiguo$/, (m) => `${m[1]} events · Page ${m[2]} · ordered by receipt, newest first`],
  [/^(\d+) de (\d+) registros con resultado$/, (m) => `${m[1]} of ${m[2]} records with a result`],
  [/^(\d+) en proceso$/, (m) => `${m[1]} processing`],
  [/^(\d+) en espera$/, (m) => `${m[1]} waiting`],
  [/^(\d+) fallidos$/, (m) => `${m[1]} failed`],
  [/^(\d+) bloqueados$/, (m) => `${m[1]} blocked`],
  [/^(\d+) sin resultado$/, (m) => `${m[1]} without result`],
  [/^(\d+) detenidos por el operador$/, (m) => `${m[1]} stopped by the operator`],
  [/^(\d+) locales$/, (m) => `${m[1]} local`],
  [/^Notificaciones, (\d+) sin leer$/, (m) => `Notifications, ${m[1]} unread`],
  [/^Notificaciones, ninguna sin leer$/, () => "Notifications, none unread"],
  [/^(\d+) sin leer$/, (m) => `${m[1]} unread`],
  [/^(\d+) versiones · Página (\d+) de (\d+)$/, (m) => `${m[1]} versions · Page ${m[2]} of ${m[3]}`],
  [/^(\d+) de (\d+)$/, (m) => `${m[1]} of ${m[2]}`],
  [/^(\d+) reglas?$/, (m) => `${m[1]} rules`],
  [/^(\d+) fuentes?$/, (m) => `${m[1]} sources`],
];

export function translateText(text: string, lang: Lang): string {
  if (lang === "es" || !text) return text;
  const exact = EN[text];
  if (exact) return exact;
  for (const [pattern, map] of PATTERNS) {
    const match = text.match(pattern);
    if (match) return map(match);
  }
  return text;
}

interface I18nValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
}

const I18nContext = createContext<I18nValue>({ lang: "es", setLang: () => {} });

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    try {
      return pickLang({
        search: typeof location !== "undefined" ? location.search : "",
        stored: typeof localStorage !== "undefined" ? localStorage.getItem(STORAGE_KEY) : null,
        languages: typeof navigator !== "undefined" ? navigator.languages : undefined,
      });
    } catch {
      return "es";
    }
  });

  activeLocale = lang === "en" ? "en-US" : "es-CR";

  const setLang = (next: Lang) => {
    try {
      localStorage.setItem(STORAGE_KEY, next);
      const url = new URL(location.href);
      url.searchParams.set("lang", next);
      history.replaceState(null, "", url);
    } catch {
      // Sin URL/localStorage: el idioma vive solo en memoria.
    }
    // Un reload evita mezclar nodos ya renderizados en español con el inglés.
    location.reload();
  };

  useEffect(() => {
    activeLocale = lang === "en" ? "en-US" : "es-CR";
    try {
      document.documentElement.lang = lang;
    } catch {}
    if (lang !== "en" || typeof document === "undefined") return;

    const skip = (element: Element | null) =>
      !!element && ["CODE", "PRE", "SCRIPT", "STYLE", "TEXTAREA"].includes(element.tagName);
    const textNode = (node: Text) => {
      if (skip(node.parentElement)) return;
      const value = node.nodeValue ?? "";
      const translated = translateText(value, lang);
      if (translated !== value) node.nodeValue = translated;
    };
    const attributes = (element: Element) => {
      if (skip(element)) return;
      for (const name of ["title", "placeholder", "aria-label", "alt"]) {
        const value = element.getAttribute(name);
        if (!value) continue;
        const translated = translateText(value, lang);
        if (translated !== value) element.setAttribute(name, translated);
      }
    };
    const walk = (node: Node) => {
      if (node.nodeType === Node.TEXT_NODE) textNode(node as Text);
      else if (node.nodeType === Node.ELEMENT_NODE) {
        attributes(node as Element);
        node.childNodes.forEach(walk);
      }
    };

    walk(document.body);
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "characterData") textNode(mutation.target as Text);
        else if (mutation.type === "attributes") attributes(mutation.target as Element);
        else mutation.addedNodes.forEach(walk);
      }
    });
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: ["title", "placeholder", "aria-label", "alt"],
    });
    return () => observer.disconnect();
  }, [lang]);

  const value = useMemo(() => ({ lang, setLang }), [lang]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  return useContext(I18nContext);
}

export function LangSwitch() {
  const { lang, setLang } = useI18n();
  return (
    <span className="lang-switch" role="group" aria-label="Language / Idioma">
      <button type="button" aria-pressed={lang === "es"} onClick={() => setLang("es")} title="Español">
        ES
      </button>
      <button type="button" aria-pressed={lang === "en"} onClick={() => setLang("en")} title="English">
        EN
      </button>
    </span>
  );
}
