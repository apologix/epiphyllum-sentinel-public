//! Límites observables por servicio (OBS-01): validación cerrada de entradas
//! del perfil, coincidencia de rutas, detección determinista de traversal y
//! clasificación de evidencia HTTP/estructura. Todo es backend determinista:
//! el modelo nunca crea, edita ni propone entradas efectivas, y ninguna
//! clasificación afirma compromiso: «impacto confirmado» exige evidencia
//! adicional explícita que este módulo no inventa.
use crate::{api::ApiError, *};
use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

pub const SCOPES: [&str; 5] = [
    "http",
    "filesystem",
    "authentication",
    "application",
    "source",
];
pub const EXPOSURES: [&str; 4] = ["public", "authenticated", "internal", "sensitive"];
pub const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
pub const MAX_ENTRIES_PER_SERVICE: i64 = 200;
pub const TEMPLATES: [(&str, &str, i64, i64, &str); 5] = [
    (
        "request_outside_declared_surface",
        "Solicitud fuera de la superficie declarada",
        3,
        300,
        "low",
    ),
    (
        "encoded_path_traversal",
        "Intento de path traversal (codificado u observado)",
        1,
        300,
        "medium",
    ),
    (
        "ambiguous_request_normalization",
        "Normalización de solicitud ambigua",
        1,
        300,
        "low",
    ),
    (
        "unexpected_structure_change",
        "Cambio de estructura no esperado",
        1,
        300,
        "medium",
    ),
    (
        "sensitive_structure_change",
        "Cambio en zona sensible de la estructura",
        1,
        300,
        "high",
    ),
];

fn bad(msg: &str) -> anyhow::Error {
    anyhow::anyhow!("observability_invalid: {msg}")
}

/// Valida y normaliza la configuración cerrada de una entrada según su ámbito.
/// Sin regex, sin scripts, sin URLs completas, sin rutas de host.
pub fn validate_entry(scope: &str, entry_kind: &str, config: &Value) -> anyhow::Result<Value> {
    if !SCOPES.contains(&scope) {
        return Err(bad("ámbito desconocido"));
    }
    match (scope, entry_kind) {
        ("http", "route") => {
            let pattern = config["path_pattern"].as_str().unwrap_or("");
            let kind = config["match_kind"].as_str().unwrap_or("");
            validate_path_pattern(pattern, kind)?;
            let exposure = config["exposure"].as_str().unwrap_or("");
            if !EXPOSURES.contains(&exposure) {
                return Err(bad("exposición desconocida"));
            }
            let methods = config["allowed_methods"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if methods.is_empty() || methods.len() > METHODS.len() {
                return Err(bad("métodos: entre 1 y 7"));
            }
            let mut normalized_methods = Vec::new();
            for m in &methods {
                let m = m.as_str().unwrap_or("");
                if !METHODS.contains(&m) || normalized_methods.contains(&m) {
                    return Err(bad("método no permitido o duplicado"));
                }
                normalized_methods.push(m);
            }
            let expected = config["expected_behavior"].as_str().unwrap_or("");
            if expected.chars().count() > 200 {
                return Err(bad("comportamiento esperado demasiado largo"));
            }
            Ok(
                json!({"path_pattern":pattern,"match_kind":kind,"exposure":exposure,"allowed_methods":normalized_methods,"expected_behavior":expected}),
            )
        }
        ("filesystem", "zone") => {
            let root = config["root_alias"].as_str().unwrap_or("");
            if root != "demo-logs" && root != "external" {
                return Err(bad("la raíz debe ser una raíz allowlisted del servicio"));
            }
            let directory = config["directory"].as_str().unwrap_or("");
            if !directory.is_empty()
                && (directory.len() > 64
                    || !directory
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            {
                return Err(bad("directorio inválido: nombre simple de un nivel"));
            }
            let sensitivity = config["sensitivity"].as_str().unwrap_or("");
            if sensitivity != "expected" && sensitivity != "sensitive" {
                return Err(bad("sensibilidad desconocida"));
            }
            let expected_change = config["expected_change"].as_bool().unwrap_or(false);
            Ok(
                json!({"root_alias":root,"directory":directory,"sensitivity":sensitivity,"expected_change":expected_change}),
            )
        }
        ("authentication" | "application" | "source", "note") => {
            let expected = config["expected_behavior"].as_str().unwrap_or("");
            if expected.is_empty() || expected.chars().count() > 500 {
                return Err(bad(
                    "la nota requiere un comportamiento esperado de 1 a 500 caracteres",
                ));
            }
            Ok(json!({"expected_behavior":expected}))
        }
        _ => Err(bad("tipo de entrada no permitido para el ámbito")),
    }
}

pub fn validate_path_pattern(pattern: &str, kind: &str) -> anyhow::Result<()> {
    if pattern.is_empty() || pattern.len() > 200 {
        return Err(bad("patrón: entre 1 y 200 caracteres"));
    }
    if !pattern.starts_with('/') {
        return Err(bad(
            "el patrón debe ser una ruta absoluta que empieza con /",
        ));
    }
    if pattern.contains("://") || pattern.contains('\\') || pattern.contains('\0') {
        return Err(bad(
            "no se permiten URLs completas ni separadores de Windows",
        ));
    }
    if pattern.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(bad(
            "no se permiten segmentos . ni .. en un patrón declarado",
        ));
    }
    if pattern.contains('%') {
        return Err(bad("el patrón se declara ya decodificado, sin %"));
    }
    match kind {
        "exact" => {
            if pattern.contains('{') || pattern.contains('}') || pattern.contains('*') {
                return Err(bad("exact no admite comodines ni segmentos {nombre}"));
            }
        }
        "prefix" => {
            if !pattern.ends_with('/') {
                return Err(bad("prefix debe terminar en / para ser inequívoco"));
            }
            if pattern.contains('{') || pattern.contains('}') || pattern.contains('*') {
                return Err(bad("prefix no admite comodines ni segmentos {nombre}"));
            }
        }
        "template" => {
            if pattern.contains('*') {
                return Err(bad("template no admite comodines libres"));
            }
            for seg in pattern.split('/') {
                if seg.contains('{') || seg.contains('}') {
                    let valid = seg.len() > 2
                        && seg.starts_with('{')
                        && seg.ends_with('}')
                        && seg[1..seg.len() - 1]
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_');
                    if !valid {
                        return Err(bad("segmento de plantilla inválido: use {nombre} completo"));
                    }
                }
            }
        }
        _ => return Err(bad("tipo de coincidencia desconocido")),
    }
    Ok(())
}

/// Coincidencia cerrada de una ruta normalizada contra un patrón declarado.
pub fn path_matches(pattern: &str, kind: &str, path: &str) -> bool {
    match kind {
        "exact" => pattern == path,
        "prefix" => path == pattern.trim_end_matches('/') || path.starts_with(pattern),
        "template" => {
            let p: Vec<&str> = pattern.split('/').collect();
            let a: Vec<&str> = path.split('/').collect();
            p.len() == a.len()
                && p.iter().zip(a.iter()).all(|(ps, asg)| {
                    if ps.starts_with('{') && ps.ends_with('}') {
                        !asg.is_empty()
                    } else {
                        ps == asg
                    }
                })
        }
        _ => false,
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Traversal {
    pub plain: bool,
    pub encoded: bool,
    pub double_encoded: bool,
}

impl Traversal {
    pub fn any(&self) -> bool {
        self.plain || self.encoded || self.double_encoded
    }
}

fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn has_traversal_segments(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    lower.split('/').any(|seg| seg == "..")
}

/// Detecta traversal en el target tal como llegó (antes de normalizar) y, si
/// no hay target crudo, en la ruta normalizada disponible. Señal informativa:
/// no afirma lectura ni acceso.
pub fn detect_traversal(raw_target: Option<&str>, normalized_path: &str) -> Traversal {
    let subject = raw_target.unwrap_or(normalized_path);
    let lower = subject.to_ascii_lowercase();
    let mut t = Traversal::default();
    if has_traversal_segments(subject) {
        t.plain = true;
    }
    if lower.contains("%252e") {
        t.double_encoded = true;
        t.encoded = true;
    }
    let decoded = percent_decode_once(&lower);
    if decoded != lower && has_traversal_segments(&decoded) {
        t.encoded = true;
    }
    t
}

/// ¿La normalización del servidor oculta la forma de la solicitud? Solo se
/// puede afirmar con target crudo: si al decodificar una vez el target se
/// obtiene otra ruta distinta de la normalizada, la correspondencia es
/// ambigua y no se reconstruye la original con certeza.
pub fn normalization_is_ambiguous(raw_target: Option<&str>, normalized_path: &str) -> bool {
    let Some(raw) = raw_target else { return false };
    if raw == normalized_path {
        return false;
    }
    let decoded = percent_decode_once(raw);
    decoded != normalized_path && decoded != raw
}

#[derive(Debug, Clone)]
pub struct Classification {
    pub kind: &'static str,
    pub matched_entry_id: Option<Uuid>,
    pub matched_revision: Option<i32>,
    pub reason: Value,
}

/// Clasifica una evidencia HTTP contra las entradas http activas del perfil.
/// `entries`: (entry_id, revision, config) ya validadas al guardar.
pub fn classify_http(http: Option<&Value>, entries: &[(Uuid, i32, Value)]) -> Classification {
    let none = |kind: &'static str, reason: Value| Classification {
        kind,
        matched_entry_id: None,
        matched_revision: None,
        reason,
    };
    let Some(http) = http else {
        return none(
            "insufficient_evidence",
            json!({"detail":"el registro no aporta evidencia HTTP estructurada (método/ruta/estado)"}),
        );
    };
    let normalized = http["normalized_path"].as_str().unwrap_or("");
    let raw = http["raw_target"].as_str();
    let origin = http["origin"].as_str().unwrap_or("");
    let method = http["method"].as_str().unwrap_or("");
    // Ruta observada: la normalizada cuando la fuente la aporta; si solo hay
    // target crudo (raw_only), se clasifica contra él sin inventar una
    // normalización que Sentinel no conoce.
    let observed = if !normalized.is_empty() {
        normalized
    } else {
        raw.unwrap_or("")
    };
    if observed.is_empty() {
        return none(
            "insufficient_evidence",
            json!({"detail":"la evidencia HTTP no incluye ruta"}),
        );
    }
    let mut base = json!({"observed_path":observed,"origin":origin,"method":method});
    if !normalized.is_empty() {
        base["normalized_path"] = json!(normalized);
    }
    if let Some(r) = raw {
        base["raw_target"] = json!(r);
    }
    if normalized.is_empty() {
        base["normalization"] = json!("unknown");
        base["normalization_note"] = json!(
            "la fuente solo aporta el target crudo: Sentinel no conoce la normalización real del servidor"
        );
    }
    if entries.is_empty() {
        let mut reason = base.clone();
        reason["detail"] = json!("el servicio no tiene superficie HTTP declarada");
        return none("boundary_unknown", reason);
    }
    let traversal = detect_traversal(raw, observed);
    let matched = entries.iter().find(|(_, _, c)| {
        path_matches(
            c["path_pattern"].as_str().unwrap_or(""),
            c["match_kind"].as_str().unwrap_or(""),
            observed,
        )
    });
    // El traversal conserva prioridad como intento aunque el método tampoco
    // esté permitido: es la señal más grave y no afirma acceso.
    if traversal.any() {
        let mut reason = base.clone();
        reason["detail"] = json!(
            "se observó un intento de traversal en la solicitud; no prueba lectura ni acceso al recurso"
        );
        reason["plain"] = json!(traversal.plain);
        reason["encoded"] = json!(traversal.encoded);
        reason["double_encoded"] = json!(traversal.double_encoded);
        return Classification {
            kind: "encoded_traversal_attempt",
            matched_entry_id: matched.map(|(id, _, _)| *id),
            matched_revision: matched.map(|(_, rev, _)| *rev),
            reason,
        };
    }
    if let Some((id, rev, c)) = matched {
        let allowed: Vec<&str> = c["allowed_methods"]
            .as_array()
            .map(|a| a.iter().filter_map(|m| m.as_str()).collect())
            .unwrap_or_default();
        if !method.is_empty() && !allowed.contains(&method) {
            let mut reason = base.clone();
            reason["detail"] = json!(
                "la ruta coincide con la superficie declarada pero el método no está permitido en esa entrada"
            );
            reason["pattern"] = c["path_pattern"].clone();
            reason["allowed_methods"] = c["allowed_methods"].clone();
            return Classification {
                kind: "method_not_allowed",
                matched_entry_id: Some(*id),
                matched_revision: Some(*rev),
                reason,
            };
        }
        let mut reason = base.clone();
        reason["detail"] = json!("la ruta y el método coinciden con la superficie declarada");
        reason["pattern"] = c["path_pattern"].clone();
        reason["exposure"] = c["exposure"].clone();
        reason["allowed_methods"] = c["allowed_methods"].clone();
        return Classification {
            kind: "within_declared_boundary",
            matched_entry_id: Some(*id),
            matched_revision: Some(*rev),
            reason,
        };
    }
    // La ambigüedad de normalización solo se puede afirmar cuando existen el
    // target crudo y la ruta normalizada; con raw_only no se afirma.
    if !normalized.is_empty() && normalization_is_ambiguous(raw, normalized) {
        let mut reason = base.clone();
        reason["detail"] = json!(
            "el servidor normalizó la solicitud y la forma original no coincide con una decodificación simple; no se reconstruye con certeza"
        );
        return none("ambiguous_normalization", reason);
    }
    let mut reason = base;
    reason["detail"] = json!(
        "la ruta está fuera de la superficie declarada del servicio; es una señal sospechosa, no un acceso confirmado"
    );
    none("outside_declared_boundary", reason)
}

/// Huella del perfil activo de un servicio: hash de sus entradas activas
/// (id, revisión y hash de configuración ordenados). Cambia con cualquier
/// edición/retiro y se congela en clasificaciones y snapshots.
pub fn fingerprint(entries: &[(Uuid, i32, String)]) -> String {
    let mut parts: Vec<String> = entries
        .iter()
        .map(|(id, rev, h)| format!("{id}:{rev}:{h}"))
        .collect();
    parts.sort();
    hash(parts.join("|"))
}

pub async fn active_entries<'e, E>(
    exec: E,
    service_id: Uuid,
    scope: Option<&str>,
) -> anyhow::Result<Vec<(Uuid, i32, Value, String)>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let rows = sqlx::query(
        "SELECT DISTINCT ON (entry_id) entry_id,revision,config,config_hash FROM service_profile_entries WHERE service_id=$1 AND status='active' AND ($2::text IS NULL OR scope=$2) ORDER BY entry_id,revision DESC",
    )
    .bind(service_id)
    .bind(scope)
    .fetch_all(exec)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("entry_id"),
                r.get("revision"),
                r.get("config"),
                r.get("config_hash"),
            )
        })
        .collect())
}

pub async fn profile_for_service(pool: &sqlx::PgPool, service_id: Uuid) -> anyhow::Result<Value> {
    let rows = sqlx::query(
        "SELECT DISTINCT ON (entry_id) entry_id,revision,scope,entry_kind,config,description,status,config_hash,created_at FROM service_profile_entries WHERE service_id=$1 ORDER BY entry_id,revision DESC",
    )
    .bind(service_id)
    .fetch_all(pool)
    .await?;
    let entries: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({"entry_id":r.get::<Uuid,_>("entry_id"),"revision":r.get::<i32,_>("revision"),"scope":r.get::<String,_>("scope"),"entry_kind":r.get::<String,_>("entry_kind"),"config":r.get::<Value,_>("config"),"description":r.get::<String,_>("description"),"status":r.get::<String,_>("status"),"created_at":r.get::<chrono::DateTime<chrono::Utc>,_>("created_at")})
        })
        .collect();
    let active: Vec<(Uuid, i32, String)> = rows
        .iter()
        .filter(|r| r.get::<String, _>("status") == "active")
        .map(|r| {
            (
                r.get::<Uuid, _>("entry_id"),
                r.get::<i32, _>("revision"),
                r.get::<String, _>("config_hash"),
            )
        })
        .collect();
    Ok(json!({"service_id":service_id,"fingerprint":fingerprint(&active),"entries":entries}))
}

/// Contexto de observabilidad para el snapshot de un job (acotado por
/// diseño, corrección REVIEW-OBS-01): por servicio se incluye la huella del
/// perfil, el total de entradas activas y su conteo por ámbito, pero solo
/// las entradas relevantes para la evidencia de esta incidencia (las que
/// alguna clasificación citó o cuyo patrón coincide con una ruta observada),
/// con el conteo y la razón de las omitidas. Un perfil válido grande nunca
/// bloquea el análisis por sí solo.
pub async fn context_for_incident(app: &App, service_ids: &[Uuid], event_ids: &[Uuid]) -> Value {
    let classifications: Vec<Value> = if event_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar::<_, Value>(
            "SELECT jsonb_build_object('event_id',c.event_id,'classification',c.classification,'profile_fingerprint',c.profile_fingerprint,'matched_entry_id',c.matched_entry_id,'matched_revision',c.matched_revision,'reason',c.reason,'http',e.http) FROM event_classifications c JOIN events e ON e.id=c.event_id WHERE c.event_id = ANY($1)",
        )
        .bind(event_ids)
        .fetch_all(&app.pool)
        .await
        .unwrap_or_default()
    };
    // Entradas relevantes: citadas por una clasificación o cuyo patrón http
    // coincide con la ruta observada de un evento clasificado.
    let mut relevant_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut observed_paths: Vec<String> = Vec::new();
    for c in &classifications {
        if let Some(id) = c["matched_entry_id"].as_str() {
            relevant_ids.insert(id.to_string());
        }
        if let Some(p) = c["reason"]["observed_path"].as_str() {
            observed_paths.push(p.to_string());
        }
    }
    let mut profiles = Vec::new();
    for sid in service_ids {
        let Ok(full) = profile_for_service(&app.pool, *sid).await else {
            continue;
        };
        let entries = full["entries"].as_array().cloned().unwrap_or_default();
        profiles.push(summarize_profile(
            *sid,
            &full["fingerprint"],
            &entries,
            &relevant_ids,
            &observed_paths,
        ));
    }
    json!({"profiles":profiles,"classifications":classifications})
}

/// Resumen acotado de un perfil para el snapshot: totales y conteos por
/// ámbito siempre; entradas completas solo las relevantes (citadas por una
/// clasificación o cuyo patrón http coincide con una ruta observada), con
/// tope de 20 y conteo explícito de omitidas. Función pura.
pub fn summarize_profile(
    service_id: Uuid,
    fingerprint: &Value,
    entries: &[Value],
    relevant_ids: &std::collections::HashSet<String>,
    observed_paths: &[String],
) -> Value {
    let active: Vec<&Value> = entries.iter().filter(|e| e["status"] == "active").collect();
    let mut by_scope = json!({});
    for scope in SCOPES {
        by_scope[scope] = json!(active.iter().filter(|e| e["scope"] == scope).count());
    }
    let mut relevant: Vec<Value> = Vec::new();
    for e in &active {
        let is_cited = relevant_ids.contains(e["entry_id"].as_str().unwrap_or(""));
        let matches_observed = e["scope"] == "http"
            && observed_paths.iter().any(|p| {
                path_matches(
                    e["config"]["path_pattern"].as_str().unwrap_or(""),
                    e["config"]["match_kind"].as_str().unwrap_or(""),
                    p,
                )
            });
        if is_cited || matches_observed {
            relevant.push((*e).clone());
        }
    }
    let total = active.len();
    relevant.truncate(20);
    let included = relevant.len();
    let omitted = total.saturating_sub(included);
    json!({
        "service_id": service_id,
        "fingerprint": fingerprint,
        "active_entries_total": total,
        "by_scope": by_scope,
        "relevant_entries": relevant,
        "omitted_entries": omitted,
        "omitted_reason": if omitted > 0 {
            "resumen acotado del snapshot: se incluyen solo las entradas relevantes para la evidencia de esta incidencia; el perfil completo sigue disponible en Editar servicio"
        } else {
            ""
        },
    })
}

/// Clasifica rutas nuevas de un diff de estructura contra las zonas
/// declaradas del servicio (misma raíz+directorio que la captura). Un archivo
/// nuevo es una señal de cambio: jamás confirma webshell ni compromiso.
pub fn classify_structure_added(
    root_alias: &str,
    directory: &str,
    added: &[String],
    zones: &[(Uuid, i32, Value)],
) -> Vec<(String, &'static str, Option<Uuid>)> {
    let zone = zones.iter().find(|(_, _, c)| {
        c["root_alias"].as_str() == Some(root_alias)
            && c["directory"].as_str().unwrap_or("") == directory
    });
    added
        .iter()
        .map(|path| match zone {
            Some((id, _, c)) if c["sensitivity"].as_str() == Some("sensitive") => {
                (path.clone(), "sensitive_structure_change", Some(*id))
            }
            Some((id, _, c)) if c["expected_change"].as_bool() == Some(true) => {
                (path.clone(), "within_declared_boundary", Some(*id))
            }
            Some((id, _, _)) => (path.clone(), "unexpected_structure_change", Some(*id)),
            None => (path.clone(), "unexpected_structure_change", None),
        })
        .collect()
}

/// Conjunto inicial explícito del laboratorio Nginx (acción del operador,
/// editable y visible; no se aplica solo ni se infiere de logs).
pub fn lab_seed() -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "route",
            json!({"path_pattern":"/","match_kind":"exact","exposure":"public","allowed_methods":["GET","HEAD"],"expected_behavior":"Portada pública del laboratorio"}),
            "Raíz pública del sitio de laboratorio",
        ),
        (
            "route",
            json!({"path_pattern":"/secure/","match_kind":"prefix","exposure":"authenticated","allowed_methods":["GET","HEAD","POST"],"expected_behavior":"Zona con autenticación básica; fallos repetidos son señal R1"}),
            "Zona autenticada del laboratorio",
        ),
        (
            "route",
            json!({"path_pattern":"/files/","match_kind":"prefix","exposure":"public","allowed_methods":["GET","HEAD"],"expected_behavior":"Archivos públicos controlados; cualquier salida de este prefijo es sospechosa"}),
            "Archivos públicos controlados",
        ),
    ]
}

// ---------- API (CRUD versionado del perfil) ----------

fn api_invalid(msg: &str) -> ApiError {
    // El mensaje de validación es cerrado y propio; se devuelve como código
    // estable para no filtrar detalles internos.
    let _ = msg;
    ApiError(StatusCode::BAD_REQUEST, "observability_invalid")
}

async fn require_service(app: &App, service_id: Uuid) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM services WHERE id=$1 AND deleted_at IS NULL)",
    )
    .bind(service_id)
    .fetch_one(&app.pool)
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    if exists {
        Ok(())
    } else {
        Err(ApiError(StatusCode::NOT_FOUND, "service_not_found"))
    }
}

fn entry_json(r: &sqlx::postgres::PgRow) -> Value {
    json!({"entry_id":r.get::<Uuid,_>("entry_id"),"revision":r.get::<i32,_>("revision"),"service_id":r.get::<Uuid,_>("service_id"),"scope":r.get::<String,_>("scope"),"entry_kind":r.get::<String,_>("entry_kind"),"config":r.get::<Value,_>("config"),"description":r.get::<String,_>("description"),"status":r.get::<String,_>("status"),"created_by":r.get::<String,_>("created_by"),"created_at":r.get::<chrono::DateTime<chrono::Utc>,_>("created_at")})
}

pub async fn list_entries(
    app: &App,
    service_id: Uuid,
    q: &HashMap<String, String>,
) -> Result<Value, ApiError> {
    require_service(app, service_id).await?;
    let limit: i64 = q
        .get("limit")
        .and_then(|x| x.parse().ok())
        .filter(|n| [10, 25, 50].contains(n))
        .unwrap_or(10);
    let offset: i64 = q
        .get("offset")
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
        .max(0);
    let scope = q.get("scope").map(|s| s.as_str()).unwrap_or("");
    let status = q.get("status").map(|s| s.as_str()).unwrap_or("");
    let exposure = q.get("exposure").map(|s| s.as_str()).unwrap_or("");
    let text = q.get("q").map(|s| s.to_lowercase()).unwrap_or_default();
    let rows = sqlx::query(
        "SELECT * FROM (SELECT DISTINCT ON (entry_id) * FROM service_profile_entries WHERE service_id=$1 ORDER BY entry_id,revision DESC) latest WHERE ($2='' OR scope=$2) AND ($3='' OR status=$3) AND ($4='' OR config->>'exposure'=$4) AND ($5='' OR lower(description||' '||config::text) LIKE '%'||$5||'%') ORDER BY scope,entry_id",
    )
    .bind(service_id).bind(scope).bind(status).bind(exposure).bind(text)
    .fetch_all(&app.pool).await.map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    let total = rows.len() as i64;
    let items: Vec<Value> = rows
        .iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(entry_json)
        .collect();
    let profile = profile_for_service(&app.pool, service_id)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    Ok(
        json!({"items":items,"total":total,"limit":limit,"offset":offset,"fingerprint":profile["fingerprint"]}),
    )
}

struct EntryDraft<'a> {
    scope: &'a str,
    entry_kind: &'a str,
    config: Value,
    description: &'a str,
    status: &'a str,
}

async fn insert_revision(
    app: &App,
    service_id: Uuid,
    entry_id: Uuid,
    draft: EntryDraft<'_>,
) -> Result<Value, ApiError> {
    let (scope, entry_kind, config, description, status) = (
        draft.scope,
        draft.entry_kind,
        draft.config,
        draft.description,
        draft.status,
    );
    let config_hash = hash(config.to_string());
    let row = sqlx::query(
        "INSERT INTO service_profile_entries(entry_id,revision,service_id,scope,entry_kind,config,description,status,config_hash) VALUES($1,COALESCE((SELECT max(revision) FROM service_profile_entries WHERE entry_id=$1),0)+1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
    )
    .bind(entry_id).bind(service_id).bind(scope).bind(entry_kind).bind(&config)
    .bind(description).bind(status).bind(config_hash)
    .fetch_one(&app.pool).await.map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    Ok(entry_json(&row))
}

pub async fn create_entry(app: &App, service_id: Uuid, body: &Value) -> Result<Value, ApiError> {
    require_service(app, service_id).await?;
    let scope = body["scope"].as_str().unwrap_or("");
    let entry_kind = body["entry_kind"].as_str().unwrap_or("");
    let config = validate_entry(scope, entry_kind, &body["config"])
        .map_err(|e| api_invalid(&e.to_string()))?;
    let description = body["description"].as_str().unwrap_or("");
    if description.chars().count() > 300 {
        return Err(api_invalid("descripción demasiado larga"));
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT entry_id) FROM service_profile_entries WHERE service_id=$1",
    )
    .bind(service_id)
    .fetch_one(&app.pool)
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    if count >= MAX_ENTRIES_PER_SERVICE {
        return Err(api_invalid("límite de entradas por servicio alcanzado"));
    }
    insert_revision(
        app,
        service_id,
        Uuid::new_v4(),
        EntryDraft {
            scope,
            entry_kind,
            config,
            description,
            status: "active",
        },
    )
    .await
}

async fn latest_entry(
    app: &App,
    service_id: Uuid,
    entry_id: Uuid,
) -> Result<sqlx::postgres::PgRow, ApiError> {
    sqlx::query(
        "SELECT * FROM service_profile_entries WHERE service_id=$1 AND entry_id=$2 ORDER BY revision DESC LIMIT 1",
    )
    .bind(service_id).bind(entry_id)
    .fetch_optional(&app.pool).await.map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
    .ok_or(ApiError(StatusCode::NOT_FOUND, "entry_not_found"))
}

pub async fn update_entry(
    app: &App,
    service_id: Uuid,
    entry_id: Uuid,
    body: &Value,
) -> Result<Value, ApiError> {
    let latest = latest_entry(app, service_id, entry_id).await?;
    let scope: String = latest.get("scope");
    let entry_kind: String = latest.get("entry_kind");
    let config = if body.get("config").is_some() {
        validate_entry(&scope, &entry_kind, &body["config"])
            .map_err(|e| api_invalid(&e.to_string()))?
    } else {
        latest.get("config")
    };
    let description = body["description"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| latest.get("description"));
    if description.chars().count() > 300 {
        return Err(api_invalid("descripción demasiado larga"));
    }
    let current_status: String = latest.get("status");
    let status: &str = body["status"].as_str().unwrap_or(&current_status);
    if status != "active" && status != "retired" {
        return Err(api_invalid("estado desconocido"));
    }
    insert_revision(
        app,
        service_id,
        entry_id,
        EntryDraft {
            scope: &scope,
            entry_kind: &entry_kind,
            config,
            description: &description,
            status,
        },
    )
    .await
}

pub async fn entry_history(app: &App, service_id: Uuid, entry_id: Uuid) -> Result<Value, ApiError> {
    require_service(app, service_id).await?;
    let rows = sqlx::query(
        "SELECT * FROM service_profile_entries WHERE service_id=$1 AND entry_id=$2 ORDER BY revision DESC",
    )
    .bind(service_id).bind(entry_id)
    .fetch_all(&app.pool).await.map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    if rows.is_empty() {
        return Err(ApiError(StatusCode::NOT_FOUND, "entry_not_found"));
    }
    Ok(json!({"items":rows.iter().map(entry_json).collect::<Vec<_>>()}))
}

pub async fn revert_entry(
    app: &App,
    service_id: Uuid,
    entry_id: Uuid,
    body: &Value,
) -> Result<Value, ApiError> {
    let revision: i32 = body["revision"].as_i64().unwrap_or(0) as i32;
    let target = sqlx::query(
        "SELECT * FROM service_profile_entries WHERE service_id=$1 AND entry_id=$2 AND revision=$3",
    )
    .bind(service_id)
    .bind(entry_id)
    .bind(revision)
    .fetch_optional(&app.pool)
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
    .ok_or(ApiError(StatusCode::NOT_FOUND, "revision_not_found"))?;
    insert_revision(
        app,
        service_id,
        entry_id,
        EntryDraft {
            scope: &target.get::<String, _>("scope"),
            entry_kind: &target.get::<String, _>("entry_kind"),
            config: target.get("config"),
            description: &target.get::<String, _>("description"),
            status: &target.get::<String, _>("status"),
        },
    )
    .await
}

pub async fn seed_lab(app: &App, service_id: Uuid) -> Result<Value, ApiError> {
    require_service(app, service_id).await?;
    let existing: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT entry_id) FROM service_profile_entries WHERE service_id=$1 AND scope='http'",
    )
    .bind(service_id)
    .fetch_one(&app.pool)
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    if existing > 0 {
        return Err(ApiError(StatusCode::CONFLICT, "lab_seed_already_applied"));
    }
    let mut created = Vec::new();
    for (kind, config, description) in lab_seed() {
        let entry_kind = if kind == "route" { "route" } else { kind };
        created.push(
            insert_revision(
                app,
                service_id,
                Uuid::new_v4(),
                EntryDraft {
                    scope: "http",
                    entry_kind,
                    config,
                    description,
                    status: "active",
                },
            )
            .await?,
        );
    }
    Ok(json!({"created":created}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pattern: &str, kind: &str) -> (Uuid, i32, Value) {
        (
            Uuid::new_v4(),
            1,
            json!({"path_pattern":pattern,"match_kind":kind,"exposure":"public","allowed_methods":["GET"],"expected_behavior":""}),
        )
    }

    #[test]
    fn matching_exact_prefix_template() {
        assert!(path_matches("/", "exact", "/"));
        assert!(!path_matches("/", "exact", "/index"));
        assert!(path_matches("/files/", "prefix", "/files/archivo.txt"));
        assert!(path_matches("/files/", "prefix", "/files"));
        assert!(!path_matches("/files/", "prefix", "/filesx"));
        assert!(path_matches("/users/{id}", "template", "/users/42"));
        assert!(!path_matches("/users/{id}", "template", "/users/42/edit"));
        assert!(!path_matches("/users/{id}", "template", "/users/"));
    }

    #[test]
    fn validation_rejects_bad_patterns() {
        for (p, k) in [
            ("http://x/", "exact"),
            ("../etc", "exact"),
            ("/a/../b", "exact"),
            ("/files", "prefix"),
            ("/a/*", "template"),
            ("/a/{id", "template"),
            ("/a/%2e%2e", "exact"),
            ("relative", "exact"),
        ] {
            assert!(validate_path_pattern(p, k).is_err(), "{p} {k}");
        }
        assert!(validate_path_pattern("/secure/", "prefix").is_ok());
        assert!(validate_path_pattern("/users/{id}", "template").is_ok());
        let ok = validate_entry("http", "route", &json!({"path_pattern":"/","match_kind":"exact","exposure":"public","allowed_methods":["GET"]})).unwrap();
        assert_eq!(ok["allowed_methods"][0], "GET");
        assert!(validate_entry("http", "route", &json!({"path_pattern":"/","match_kind":"exact","exposure":"public","allowed_methods":["FETCH"]})).is_err());
        assert!(validate_entry("http", "route", &json!({"path_pattern":"/","match_kind":"exact","exposure":"public","allowed_methods":[]})).is_err());
        assert!(
            validate_entry(
                "filesystem",
                "zone",
                &json!({"root_alias":"/etc","directory":"","sensitivity":"expected"})
            )
            .is_err()
        );
        assert!(
            validate_entry(
                "filesystem",
                "zone",
                &json!({"root_alias":"external","directory":"../x","sensitivity":"expected"})
            )
            .is_err()
        );
        assert!(
            validate_entry("authentication", "note", &json!({"expected_behavior":""})).is_err()
        );
    }

    #[test]
    fn traversal_detection_variants() {
        let t = detect_traversal(Some("/files/../secret.txt"), "/secret.txt");
        assert!(t.plain && !t.encoded);
        let t = detect_traversal(Some("/files/%2e%2e/secret.txt"), "/secret.txt");
        assert!(t.encoded && !t.double_encoded);
        let t = detect_traversal(
            Some("/files/%252e%252e/secret.txt"),
            "/files/%2e%2e/secret.txt",
        );
        assert!(t.double_encoded && t.encoded);
        let t = detect_traversal(None, "/files/archivo.txt");
        assert!(!t.any());
        let t = detect_traversal(Some("/files/..\\secret.txt"), "/secret.txt");
        assert!(t.plain);
    }

    #[test]
    fn classification_matrix() {
        let entries = vec![entry("/files/", "prefix"), entry("/secure/", "prefix")];
        let within = classify_http(
            Some(&json!({"method":"GET","normalized_path":"/files/archivo.txt","status":200})),
            &entries,
        );
        assert_eq!(within.kind, "within_declared_boundary");
        let outside = classify_http(
            Some(&json!({"method":"GET","normalized_path":"/secret.txt","status":200})),
            &entries,
        );
        assert_eq!(outside.kind, "outside_declared_boundary");
        // 200 no convierte el intento en impacto: traversal con 200 sigue siendo intento
        let trav = classify_http(
            Some(
                &json!({"method":"GET","raw_target":"/files/../secret.txt","normalized_path":"/secret.txt","status":200}),
            ),
            &entries,
        );
        assert_eq!(trav.kind, "encoded_traversal_attempt");
        let enc = classify_http(
            Some(
                &json!({"method":"GET","raw_target":"/files/%2e%2e/secret.txt","normalized_path":"/secret.txt","status":404}),
            ),
            &entries,
        );
        assert_eq!(enc.kind, "encoded_traversal_attempt");
        let unknown = classify_http(
            Some(&json!({"method":"GET","normalized_path":"/x","status":200})),
            &[],
        );
        assert_eq!(unknown.kind, "boundary_unknown");
        let none = classify_http(None, &entries);
        assert_eq!(none.kind, "insufficient_evidence");
    }

    #[test]
    fn structure_added_classification() {
        let zid = Uuid::new_v4();
        let sensitive = vec![(
            zid,
            1,
            json!({"root_alias":"external","directory":"web","sensitivity":"sensitive","expected_change":false}),
        )];
        let out =
            classify_structure_added("external", "web", &["shell.php".to_string()], &sensitive);
        assert_eq!(out[0].1, "sensitive_structure_change");
        let expected = vec![(
            zid,
            1,
            json!({"root_alias":"external","directory":"web","sensitivity":"expected","expected_change":true}),
        )];
        let out =
            classify_structure_added("external", "web", &["nuevo.txt".to_string()], &expected);
        assert_eq!(out[0].1, "within_declared_boundary");
        let out = classify_structure_added("external", "web", &["nuevo.txt".to_string()], &[]);
        assert_eq!(out[0].1, "unexpected_structure_change");
    }

    #[test]
    fn method_must_match_declared_entry() {
        // GET permitido sobre ruta exacta declarada solo para GET/HEAD
        let root = (
            Uuid::new_v4(),
            1,
            json!({"path_pattern":"/","match_kind":"exact","exposure":"public","allowed_methods":["GET","HEAD"],"expected_behavior":""}),
        );
        let entries = vec![root.clone()];
        let get = classify_http(
            Some(
                &json!({"method":"GET","normalized_path":"/","status":200,"origin":"server_normalized_only"}),
            ),
            &entries,
        );
        assert_eq!(get.kind, "within_declared_boundary");
        // POST no permitido: la ruta coincide pero el método no
        let post = classify_http(
            Some(
                &json!({"method":"POST","normalized_path":"/","status":200,"origin":"server_normalized_only"}),
            ),
            &entries,
        );
        assert_eq!(post.kind, "method_not_allowed");
        assert_eq!(post.reason["pattern"], "/");
        assert_eq!(post.reason["method"], "POST");
        assert_eq!(post.reason["allowed_methods"], json!(["GET", "HEAD"]));
        assert!(post.matched_entry_id.is_some());
        // Prefijo con método permitido
        let files = (
            Uuid::new_v4(),
            1,
            json!({"path_pattern":"/files/","match_kind":"prefix","exposure":"public","allowed_methods":["GET","POST"],"expected_behavior":""}),
        );
        let up = classify_http(
            Some(&json!({"method":"POST","normalized_path":"/files/subida","status":201})),
            &[files],
        );
        assert_eq!(up.kind, "within_declared_boundary");
        // Plantilla con método permitido y con método no permitido
        let users = (
            Uuid::new_v4(),
            1,
            json!({"path_pattern":"/users/{id}","match_kind":"template","exposure":"authenticated","allowed_methods":["GET","DELETE"],"expected_behavior":""}),
        );
        let del = classify_http(
            Some(&json!({"method":"DELETE","normalized_path":"/users/42","status":200})),
            std::slice::from_ref(&users),
        );
        assert_eq!(del.kind, "within_declared_boundary");
        let put = classify_http(
            Some(&json!({"method":"PUT","normalized_path":"/users/42","status":200})),
            &[users],
        );
        assert_eq!(put.kind, "method_not_allowed");
        // El traversal conserva prioridad como intento aunque el método no sea permitido
        let trav = classify_http(
            Some(
                &json!({"method":"POST","raw_target":"/files/../secret.txt","normalized_path":"/secret.txt","status":200}),
            ),
            &[root],
        );
        assert_eq!(trav.kind, "encoded_traversal_attempt");
    }

    #[test]
    fn raw_only_combined_log_classification() {
        let entries = vec![entry("/files/", "prefix"), entry("/", "exact")];
        // Ruta dentro de superficie usando solo el target crudo
        let within = classify_http(
            Some(
                &json!({"method":"GET","raw_target":"/files/archivo.txt","status":200,"origin":"raw_only"}),
            ),
            &entries,
        );
        assert_eq!(within.kind, "within_declared_boundary");
        assert_eq!(within.reason["origin"], "raw_only");
        assert_eq!(within.reason["observed_path"], "/files/archivo.txt");
        assert_eq!(within.reason["normalization"], "unknown");
        assert!(within.reason.get("normalized_path").is_none());
        // Ruta fuera de superficie con HTTP 200: señal, no impacto confirmado
        let outside = classify_http(
            Some(
                &json!({"method":"GET","raw_target":"/secret.txt","status":200,"origin":"raw_only"}),
            ),
            &entries,
        );
        assert_eq!(outside.kind, "outside_declared_boundary");
        assert_eq!(outside.reason["observed_path"], "/secret.txt");
        // Traversal crudo sin normalizada disponible
        let trav = classify_http(
            Some(
                &json!({"method":"GET","raw_target":"/files/../secret.txt","status":404,"origin":"raw_only"}),
            ),
            &entries,
        );
        assert_eq!(trav.kind, "encoded_traversal_attempt");
        assert_eq!(trav.reason["origin"], "raw_only");
        // Sin ruta alguna sigue siendo evidencia insuficiente
        let none = classify_http(
            Some(&json!({"method":"GET","status":200,"origin":"raw_only"})),
            &entries,
        );
        assert_eq!(none.kind, "insufficient_evidence");
    }

    #[test]
    fn snapshot_profile_summary_is_bounded() {
        // Un perfil válido grande (200 entradas) se resume: solo entra la
        // relevante y las omisiones quedan contadas, nunca bloquea.
        let cited = Uuid::new_v4();
        let mut entries: Vec<Value> = (0..199)
            .map(|i| {
                json!({"entry_id":Uuid::new_v4(),"revision":1,"scope":"http","entry_kind":"route","config":{"path_pattern":format!("/r{i}/"),"match_kind":"prefix","exposure":"public","allowed_methods":["GET"],"expected_behavior":""},"description":"","status":"active"})
            })
            .collect();
        entries.push(json!({"entry_id":cited,"revision":2,"scope":"http","entry_kind":"route","config":{"path_pattern":"/files/","match_kind":"prefix","exposure":"public","allowed_methods":["GET"],"expected_behavior":""},"description":"","status":"active"}));
        let mut ids = std::collections::HashSet::new();
        ids.insert(cited.to_string());
        let out = summarize_profile(
            Uuid::new_v4(),
            &json!("fp"),
            &entries,
            &ids,
            &["/files/x".to_string()],
        );
        assert_eq!(out["active_entries_total"], 200);
        assert_eq!(out["relevant_entries"].as_array().unwrap().len(), 1);
        assert_eq!(out["omitted_entries"], 199);
        assert_eq!(out["by_scope"]["http"], 200);
    }
    #[test]
    fn fingerprint_changes_with_revision() {
        let id = Uuid::new_v4();
        let a = fingerprint(&[(id, 1, "h1".into())]);
        let b = fingerprint(&[(id, 2, "h1".into())]);
        assert_ne!(a, b);
        assert_eq!(a, fingerprint(&[(id, 1, "h1".into())]));
    }
}
