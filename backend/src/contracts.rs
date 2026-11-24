use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;
use uuid::Uuid;
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogEvent {
    pub schema_version: i32,
    pub scenario_run_id: Uuid,
    pub event_id: Uuid,
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_type: String,
    pub level: String,
    pub message: String,
    pub src_ip: Option<String>,
    pub user: Option<String>,
    pub service: Option<String>,
    pub request_id: Option<String>,
    /// Evidencia HTTP estructurada cuando el formato la aporta de verdad.
    /// Sin cuerpos, sin cabeceras de autorización y sin query string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<serde_json::Value>,
}
pub fn parse_line(bytes: &[u8]) -> anyhow::Result<LogEvent> {
    parse_line_with_class(bytes, false)
}
pub fn parse_line_with_class(bytes: &[u8], real: bool) -> anyhow::Result<LogEvent> {
    anyhow::ensure!(bytes.len() <= 65536, "line_too_large");
    let e: LogEvent = serde_json::from_slice(bytes)?;
    anyhow::ensure!(e.schema_version == 1 && e.seq > 0, "schema_invalid");
    anyhow::ensure!(
        ["auth", "app", "system"].contains(&e.source.as_str()),
        "source_invalid"
    );
    anyhow::ensure!(
        [
            "auth.failed",
            "auth.success",
            "app.error",
            "http.suspicious",
            "system.notice"
        ]
        .contains(&e.event_type.as_str()),
        "event_type_invalid"
    );
    anyhow::ensure!(
        ["info", "warning", "error"].contains(&e.level.as_str())
            && e.message.chars().count() <= 2048,
        "field_invalid"
    );
    anyhow::ensure!(
        matches!(
            (e.source.as_str(), e.event_type.as_str()),
            ("auth", "auth.failed" | "auth.success")
                | ("app", "app.error" | "http.suspicious")
                | ("system", "system.notice")
        ),
        "source_type_mismatch"
    );
    if let Some(http) = &e.http {
        let method = http["method"].as_str().unwrap_or("");
        anyhow::ensure!(
            ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"].contains(&method),
            "http_method_invalid"
        );
        for key in ["raw_target", "normalized_path"] {
            if let Some(p) = http[key].as_str() {
                anyhow::ensure!(
                    p.starts_with('/') && p.len() <= 1024 && !p.contains('?') && !p.contains('#'),
                    "http_path_invalid"
                );
            }
        }
        if let Some(status) = http["status"].as_i64() {
            anyhow::ensure!((100..=599).contains(&status), "http_status_invalid");
        }
        anyhow::ensure!(
            matches!(
                http["origin"].as_str().unwrap_or(""),
                "server_normalized_only" | "raw_only" | "raw_and_normalized"
            ),
            "http_origin_invalid"
        );
    }
    for s in [&e.user, &e.service, &e.request_id].into_iter().flatten() {
        anyhow::ensure!(s.chars().count() <= 64, "field_too_long");
    }
    if !real && let Some(user) = &e.user {
        anyhow::ensure!(user.starts_with("demo-"), "synthetic_user_required");
    }
    if let Some(ip) = &e.src_ip {
        let ip: IpAddr = ip.parse()?;
        let ok = match ip {
            IpAddr::V4(v) => {
                let o = v.octets();
                o[..3] == [192, 0, 2] || o[..3] == [198, 51, 100] || o[..3] == [203, 0, 113]
            }
            _ => false,
        };
        anyhow::ensure!(real || ok, "documentation_ip_required");
    }
    Ok(e)
}
pub fn redact(s: &str, session: &str) -> String {
    let mut out = s.to_owned();
    for pattern in [
        r#"(?i)(?:password|secret)[=:]\s*[^\s\"']+"#,
        r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        r#"(?i)bearer\s+[^\s"']+"#,
        r"(?i)(?:sk-|api[_-]?key[=: ]+|token[=: ]+)[a-z0-9_\-]{6,}",
        r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}",
    ] {
        if let Ok(re) = regex::Regex::new(pattern) {
            out = re.replace_all(&out, "[redactado]").into_owned();
        }
    }
    let re = regex::Regex::new(r"demo-[\w-]+").unwrap();
    re.replace_all(&out, |c: &regex::Captures| {
        format!(
            "usuario-{}",
            &crate::hash(format!("{session}:{}", &c[0]))[..10]
        )
    })
    .into_owned()
}
// ---------- Contrato de eventos derivados MCP (Etapas 2-3) ----------
// Esquema en planning/MCP-EVENT-CONTRACT.md §2.2/§2.5. El adaptador del
// servicio propone eventos dentro del registro de la página; este validador
// puro decide qué se persiste. La identidad, el producto y la versión del
// servicio jamás vienen del evento: los fija el backend desde la fuente
// autenticada. Los errores de enriquecimiento conservan el registro y no
// crean el evento; solo la suplantación de identidad es error de integridad.

/// Máximo de eventos derivados aceptados por registro (§2.5).
pub const DERIVED_MAX_EVENTS_PER_RECORD: usize = 4;
/// Tamaño serializado máximo de un evento derivado (§2.5).
pub const DERIVED_MAX_EVENT_BYTES: usize = 4096;
/// Máximo de claves en `attributes` (§2.2.3).
pub const DERIVED_MAX_ATTRIBUTES: usize = 8;

const DERIVED_EVENT_TYPES: [&str; 5] = [
    "auth.failed",
    "auth.success",
    "app.error",
    "http.suspicious",
    "system.notice",
];
const DERIVED_SOURCES: [&str; 3] = ["auth", "app", "system"];
const DERIVED_LEVELS: [&str; 3] = ["info", "warning", "error"];
const DERIVED_TIMESTAMP_SOURCES: [&str; 3] = [
    "producer_rfc3339",
    "producer_naive_utc",
    "syslog_context_year",
];
const DERIVED_ATTRIBUTE_KEYS: [&str; 9] = [
    "auth_method",
    "invalid_user",
    "protocol",
    "request_id",
    "session_id",
    "upstream_status",
    "db_user",
    "error_code",
    "operation",
];
const DERIVED_ALLOWED_KEYS: [&str; 12] = [
    "event_schema_version",
    "event_type",
    "source",
    "level",
    "timestamp",
    "timestamp_source",
    "src_ip",
    "username",
    "http",
    "parser_name",
    "parser_version",
    "attributes",
];
/// Campos de identidad prohibidos en un evento derivado (§2.2).
const DERIVED_IDENTITY_KEYS: [&str; 5] = ["service", "service_id", "product", "cpe", "version"];

/// Un evento derivado ya validado, listo para mapearse a una fila de `events`.
/// `username` y `attributes.db_user` viajan en claro solo dentro del canal
/// autenticado: quien persiste los seudonimiza (§2.2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedEvent {
    /// Posición 0-based dentro del array `derived_events` original; forma
    /// parte de la identidad estable (§2.4).
    pub index: usize,
    pub event_type: String,
    pub source: String,
    pub level: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub timestamp_source: Option<String>,
    pub src_ip: Option<String>,
    pub username: Option<String>,
    pub http: Option<Value>,
    pub parser_name: String,
    pub parser_version: String,
    pub attributes: Option<Value>,
}

/// Resultado de validar el array `derived_events` de un registro.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DerivedValidation {
    pub events: Vec<DerivedEvent>,
    /// Eventos de entrada que no llegaron a la salida (inválidos, duplicados
    /// internos o por encima del máximo por registro).
    pub rejected: usize,
    /// Hubo algún problema de enriquecimiento (rechazos o un timestamp
    /// descartado): el registro se anota con `mcp_derived_invalid`.
    pub issues: bool,
}

/// Errores de integridad del contrato: abortan la captura (§2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedIntegrityError {
    /// `derived_events` está presente pero no es un array.
    NotArray,
    /// Un evento declara una identidad distinta de la fuente autenticada.
    IdentityMismatch,
}

enum DerivedEventError {
    Integrity,
    Enrichment,
}

/// Identidad estable de un evento derivado (§2.4): determinista entre
/// relecturas, rotaciones ya drenadas y reintentos, sin UUID aleatorios.
pub fn derived_event_id(
    record_id: &Uuid,
    parser_name: &str,
    parser_version: &str,
    index: usize,
) -> Uuid {
    Uuid::new_v5(
        record_id,
        format!("derived:{parser_name}@{parser_version}:{index}").as_bytes(),
    )
}

/// Valida el valor de la clave `derived_events` de un registro contra el
/// contexto de la fuente autenticada (`service`/`product` del mapa fijo y la
/// versión publicada en los metadatos de la página, si la hay).
pub fn validate_derived_events(
    value: &Value,
    source_service: &str,
    source_product: &str,
    source_version: Option<&str>,
) -> Result<DerivedValidation, DerivedIntegrityError> {
    let items = value.as_array().ok_or(DerivedIntegrityError::NotArray)?;
    let mut out = DerivedValidation::default();
    let mut seen: Vec<(
        String,
        String,
        String,
        Option<DateTime<Utc>>,
        Option<String>,
        Option<String>,
    )> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match validate_derived_event(item, index, source_service, source_product, source_version) {
            Ok((event, issue)) => {
                out.issues |= issue;
                let key = (
                    event.parser_name.clone(),
                    event.parser_version.clone(),
                    event.event_type.clone(),
                    event.timestamp,
                    event.src_ip.clone(),
                    event.username.clone(),
                );
                if seen.contains(&key) || out.events.len() >= DERIVED_MAX_EVENTS_PER_RECORD {
                    out.rejected += 1;
                    out.issues = true;
                    continue;
                }
                seen.push(key);
                out.events.push(event);
            }
            Err(DerivedEventError::Integrity) => {
                return Err(DerivedIntegrityError::IdentityMismatch);
            }
            Err(DerivedEventError::Enrichment) => {
                out.rejected += 1;
                out.issues = true;
            }
        }
    }
    Ok(out)
}

fn validate_derived_event(
    value: &Value,
    index: usize,
    source_service: &str,
    source_product: &str,
    source_version: Option<&str>,
) -> Result<(DerivedEvent, bool), DerivedEventError> {
    use DerivedEventError::*;
    let object = value.as_object().ok_or(Enrichment)?;
    if serde_json::to_vec(value).map_or(true, |b| b.len() > DERIVED_MAX_EVENT_BYTES) {
        return Err(Enrichment);
    }
    // Identidad: un valor distinto del de la fuente autenticada es
    // suplantación (integridad); el campo con el valor correcto sigue siendo
    // un campo no permitido (enriquecimiento).
    for key in DERIVED_IDENTITY_KEYS {
        if let Some(claimed) = object.get(key) {
            let expected = match key {
                "service" | "service_id" => Some(source_service),
                "product" | "cpe" => Some(source_product),
                "version" => source_version,
                _ => None,
            };
            if !expected.is_some_and(|e| claimed.as_str() == Some(e)) {
                return Err(Integrity);
            }
            return Err(Enrichment);
        }
    }
    if object
        .keys()
        .any(|k| !DERIVED_ALLOWED_KEYS.contains(&k.as_str()))
    {
        return Err(Enrichment);
    }
    // Una versión de esquema futura es enriquecimiento: se conserva el
    // registro y no se crea ningún evento de esa versión.
    if object.get("event_schema_version").and_then(Value::as_i64) != Some(1) {
        return Err(Enrichment);
    }
    let event_type = object
        .get("event_type")
        .and_then(Value::as_str)
        .ok_or(Enrichment)?;
    if !DERIVED_EVENT_TYPES.contains(&event_type) {
        return Err(Enrichment);
    }
    let source = object
        .get("source")
        .and_then(Value::as_str)
        .ok_or(Enrichment)?;
    if !DERIVED_SOURCES.contains(&source)
        || !matches!(
            (source, event_type),
            ("auth", "auth.failed" | "auth.success")
                | ("app", "app.error" | "http.suspicious")
                | ("system", "system.notice")
        )
    {
        return Err(Enrichment);
    }
    let level = object
        .get("level")
        .and_then(Value::as_str)
        .ok_or(Enrichment)?;
    if !DERIVED_LEVELS.contains(&level) {
        return Err(Enrichment);
    }
    let parser_name = object
        .get("parser_name")
        .and_then(Value::as_str)
        .ok_or(Enrichment)?;
    if parser_name.is_empty()
        || parser_name.chars().count() > 32
        || !parser_name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Enrichment);
    }
    let parser_version = object
        .get("parser_version")
        .and_then(Value::as_str)
        .ok_or(Enrichment)?;
    if parser_version.is_empty()
        || parser_version.len() > 8
        || !parser_version.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Enrichment);
    }
    // Temporal (§2.3): un timestamp inutilizable se descarta solo; el resto
    // del evento puede seguir siendo válido.
    let mut issue = false;
    let mut timestamp = None;
    let mut timestamp_source = None;
    match (object.get("timestamp"), object.get("timestamp_source")) {
        (Some(raw), Some(src)) => {
            let parsed = raw
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&Utc))
                .filter(|t| (0..=4_102_444_800).contains(&t.timestamp()));
            match (
                src.as_str()
                    .is_some_and(|s| DERIVED_TIMESTAMP_SOURCES.contains(&s)),
                parsed,
            ) {
                (true, Some(t)) => {
                    timestamp = Some(t);
                    timestamp_source = src.as_str().map(str::to_owned);
                }
                _ => issue = true,
            }
        }
        (Some(_), None) => issue = true,
        (None, Some(_)) => return Err(Enrichment),
        (None, None) => {}
    }
    let src_ip = match object.get("src_ip") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let raw = v.as_str().ok_or(Enrichment)?;
            Some(raw.parse::<IpAddr>().map_err(|_| Enrichment)?.to_string())
        }
    };
    let username = match object.get("username") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let raw = v.as_str().ok_or(Enrichment)?;
            if raw.is_empty() || raw.chars().count() > 64 {
                return Err(Enrichment);
            }
            Some(raw.to_owned())
        }
    };
    let http = match object.get("http") {
        None | Some(Value::Null) => None,
        Some(v) => {
            validate_derived_http(v)?;
            Some(v.clone())
        }
    };
    let attributes = match object.get("attributes") {
        None | Some(Value::Null) => None,
        Some(v) => Some(validate_derived_attributes(v)?),
    };
    // Mínimos por tipo (§2.2.1), alineados con el «usable» de detection.rs.
    match event_type {
        "auth.failed" | "auth.success" => {
            if src_ip.is_none() || username.is_none() {
                return Err(Enrichment);
            }
        }
        "http.suspicious" => {
            let has_path = http.as_ref().is_some_and(|h| {
                h.get("raw_target").and_then(Value::as_str).is_some()
                    || h.get("normalized_path").and_then(Value::as_str).is_some()
            });
            if src_ip.is_none() || !has_path {
                return Err(Enrichment);
            }
        }
        _ => {}
    }
    Ok((
        DerivedEvent {
            index,
            event_type: event_type.to_owned(),
            source: source.to_owned(),
            level: level.to_owned(),
            timestamp,
            timestamp_source,
            src_ip,
            username,
            http,
            parser_name: parser_name.to_owned(),
            parser_version: parser_version.to_owned(),
            attributes,
        },
        issue,
    ))
}

/// El objeto `http` de un derivado se valida con las mismas reglas cerradas
/// que `parse_line_with_class` aplica al de `LogEvent`.
fn validate_derived_http(http: &Value) -> Result<(), DerivedEventError> {
    use DerivedEventError::*;
    let object = http.as_object().ok_or(Enrichment)?;
    let method = object.get("method").and_then(Value::as_str).unwrap_or("");
    if !["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"].contains(&method) {
        return Err(Enrichment);
    }
    for key in ["raw_target", "normalized_path"] {
        if let Some(path) = object.get(key) {
            let path = path.as_str().ok_or(Enrichment)?;
            if !(path.starts_with('/')
                && path.len() <= 1024
                && !path.contains('?')
                && !path.contains('#'))
            {
                return Err(Enrichment);
            }
        }
    }
    if let Some(status) = object.get("status") {
        let status = status.as_i64().ok_or(Enrichment)?;
        if !(100..=599).contains(&status) {
            return Err(Enrichment);
        }
    }
    let origin = object.get("origin").and_then(Value::as_str).unwrap_or("");
    if !matches!(
        origin,
        "server_normalized_only" | "raw_only" | "raw_and_normalized"
    ) {
        return Err(Enrichment);
    }
    Ok(())
}

fn validate_derived_attributes(value: &Value) -> Result<Value, DerivedEventError> {
    use DerivedEventError::*;
    let object = value.as_object().ok_or(Enrichment)?;
    if object.len() > DERIVED_MAX_ATTRIBUTES {
        return Err(Enrichment);
    }
    for (key, v) in object {
        if !DERIVED_ATTRIBUTE_KEYS.contains(&key.as_str()) {
            return Err(Enrichment);
        }
        let short_text = |max: usize| {
            v.as_str()
                .is_some_and(|s| !s.is_empty() && s.chars().count() <= max)
        };
        let ok = match key.as_str() {
            "auth_method" => matches!(v.as_str(), Some("password" | "publickey")),
            "invalid_user" => v.is_boolean(),
            "protocol" => v.as_str() == Some("ssh"),
            "request_id" | "session_id" | "db_user" => short_text(64),
            "upstream_status" => v.as_i64().is_some_and(|n| (100..=599).contains(&n)),
            "error_code" | "operation" => short_text(32),
            _ => false,
        };
        if !ok {
            return Err(Enrichment);
        }
    }
    Ok(value.clone())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub text: String,
    pub confidence: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRef {
    pub chunk_id: Uuid,
    pub version: i32,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClaim {
    pub event_id: Uuid,
    pub claim: String,
}
// Persist only known validation codes, never arbitrary provider text in serde errors.
pub fn validation_code(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "response_too_large" => "response_too_large",
        "invalid_chat" => "invalid_chat",
        "invalid_fact" => "invalid_fact",
        "invalid_analysis" => "invalid_analysis",
        "invalid_evidence" => "invalid_evidence",
        "invalid_policy_ref" => "invalid_policy_ref",
        "invalid_response" => "invalid_response",
        "invalid_hypothesis" => "invalid_hypothesis",
        "invalid_knowledge_ref" => "invalid_knowledge_ref",
        "invalid_review" => "invalid_review",
        "invalid_coverage" => "invalid_coverage",
        "unsupported_disposition" => "unsupported_disposition",
        "invalid_finding" => "invalid_finding",
        "missing_uncertainty" => "missing_uncertainty",
        "unsupported_quote" => "unsupported_quote",
        "context_only_finding" => "context_only_finding",
        other if other.starts_with("unknown field") => "schema_unknown_field",
        other if other.starts_with("missing field") => "schema_missing_field",
        other if other.starts_with("invalid type") => "schema_field_type",
        _ => "schema_mismatch",
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub id: Uuid,
    pub revision: i32,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisResponse {
    pub schema_version: i32,
    pub summary: String,
    pub explanation: String,
    pub evidence: Vec<EvidenceClaim>,
    pub hypotheses: Vec<Hypothesis>,
    pub knowledge_references: Vec<KnowledgeRef>,
    pub decision_policy_refs: Vec<PolicyRef>,
    pub uncertainty: Vec<String>,
    pub recommendations: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub text: String,
    pub event_ids: Vec<Uuid>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChatResponse {
    pub schema_version: i32,
    pub answer: String,
    pub facts: Vec<Fact>,
    pub hypotheses: Vec<Hypothesis>,
    pub knowledge_references: Vec<KnowledgeRef>,
    pub uncertainty: Vec<String>,
    pub human_checks: Vec<String>,
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max
}
pub fn validate_response(value: Value, kind: &str, snapshot: &Value) -> anyhow::Result<Value> {
    anyhow::ensure!(value.to_string().len() <= 32768, "response_too_large");
    if kind == "review" {
        return crate::review::validate(value, snapshot);
    }
    let ids: Vec<String> = snapshot["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["id"].as_str().map(String::from))
        .collect();
    let (version, refs, hyps, uncertainty) = if kind == "chat" {
        let r: ChatResponse = serde_json::from_value(value.clone())?;
        anyhow::ensure!(
            text(&r.answer, 4000)
                && r.facts.len() <= 50
                && r.human_checks.len() <= 5
                && r.human_checks.iter().all(|s| text(s, 500)),
            "invalid_chat"
        );
        for f in &r.facts {
            anyhow::ensure!(
                text(&f.text, 500)
                    && !f.event_ids.is_empty()
                    && f.event_ids.iter().all(|i| ids.contains(&i.to_string())),
                "invalid_fact"
            );
        }
        (
            r.schema_version,
            r.knowledge_references,
            r.hypotheses,
            r.uncertainty,
        )
    } else {
        let r: AnalysisResponse = serde_json::from_value(value.clone())?;
        anyhow::ensure!(
            text(&r.summary, 240)
                && text(&r.explanation, 4000)
                && !r.evidence.is_empty()
                && r.evidence.len() <= 50
                && (1..=5).contains(&r.recommendations.len())
                && r.recommendations.iter().all(|s| text(s, 500)),
            "invalid_analysis"
        );
        for e in &r.evidence {
            anyhow::ensure!(
                ids.contains(&e.event_id.to_string()) && text(&e.claim, 500),
                "invalid_evidence"
            );
        }
        for p in &r.decision_policy_refs {
            anyhow::ensure!(
                snapshot["policies"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|x| x["id"] == p.id.to_string() && x["revision"] == p.revision),
                "invalid_policy_ref"
            );
        }
        (
            r.schema_version,
            r.knowledge_references,
            r.hypotheses,
            r.uncertainty,
        )
    };
    anyhow::ensure!(
        version == 1
            && refs.len() <= 4
            && hyps.len() <= 5
            && (1..=10).contains(&uncertainty.len())
            && uncertainty.iter().all(|s| text(s, 500)),
        "invalid_response"
    );
    for h in hyps {
        anyhow::ensure!(
            text(&h.text, 500) && ["low", "medium", "high"].contains(&h.confidence.as_str()),
            "invalid_hypothesis"
        );
    }
    for r in refs {
        anyhow::ensure!(
            snapshot["chunks"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|c| c["chunk_id"] == r.chunk_id.to_string() && c["revision"] == r.version),
            "invalid_knowledge_ref"
        );
    }
    Ok(value)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub scope: Vec<String>,
    pub rule_ids: Vec<String>,
    pub event_types: Vec<String>,
    pub data_class: String,
    pub effect: String,
}
pub fn validate_policy(p: &Policy) -> anyhow::Result<()> {
    anyhow::ensure!(
        p.data_class == "synthetic"
            && ["allow", "deny"].contains(&p.effect.as_str())
            && !p.scope.is_empty()
            && !p.rule_ids.is_empty(),
        "invalid_policy"
    );
    anyhow::ensure!(
        p.scope
            .iter()
            .all(|s| ["analysis", "chat"].contains(&s.as_str()))
            && p.rule_ids
                .iter()
                .all(|s| ["R1", "R2", "R3", "R4", "AI"].contains(&s.as_str()))
            && p.event_types.iter().all(|s| [
                "auth.failed",
                "auth.success",
                "app.error",
                "system.notice"
            ]
            .contains(&s.as_str())),
        "invalid_policy_fields"
    );
    anyhow::ensure!(
        p.effect != "allow" || !p.rule_ids.iter().any(|s| s == "R4"),
        "R4_immutable_denial"
    );
    Ok(())
}
pub fn policy_allows(policies: &Value, kind: &str, rule: &str, event_types: &[String]) -> bool {
    if rule == "R4" {
        return false;
    }
    let mut allow = false;
    for v in policies.as_array().into_iter().flatten() {
        let Ok(p) = serde_json::from_value::<Policy>(v["definition"].clone()) else {
            return false;
        };
        if validate_policy(&p).is_err() {
            return false;
        }
        if p.scope.contains(&kind.to_string())
            && p.rule_ids.contains(&rule.to_string())
            && (p.event_types.is_empty() || event_types.iter().any(|s| p.event_types.contains(s)))
        {
            if p.effect == "deny" {
                return false;
            }
            allow = true;
        }
    }
    allow
}
pub fn mock_response(kind: &str, s: &Value) -> Value {
    if kind == "review" {
        return crate::review::mock(s);
    }
    let refs: Vec<Value> = s["chunks"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| json!({"chunk_id":c["chunk_id"],"version":c["revision"]}))
        .collect();
    let has_sources = !refs.is_empty();
    if kind == "chat" {
        json!({"schema_version":1,"answer":if has_sources {"Generación mock: el patrón determinista justifica una revisión humana; las guías citadas describen alternativas benignas y datos que faltan. No confirma una intrusión."}else{"Generación mock: falta conocimiento pertinente para responder esta pregunta con fundamento. Revise la evidencia disponible."},"facts":s["events"].as_array().into_iter().flatten().take(3).map(|e|json!({"text":format!("Evento observado: {}",e["event_type"].as_str().unwrap_or("evento")),"event_ids":[e["id"]]})).collect::<Vec<_>>(),"hypotheses":[{"text":"Podría tratarse de una configuración o credencial ficticia incorrecta.","confidence":"low"}],"knowledge_references":refs,"uncertainty":["Los datos son sintéticos y no describen un compromiso confirmado."],"human_checks":["Contrastar manualmente los eventos y las fuentes citadas."]})
    } else {
        let summary = match s["rule_id"].as_str() {
            Some("R1") => {
                "Generación mock: fallos de autenticación concentrados; una credencial incorrecta es una hipótesis que debe verificarse."
            }
            Some("R2") => {
                "Generación mock: acceso exitoso después de fallos repetidos; conviene verificar si el acceso era esperado."
            }
            Some("R3")
                if s["events"].as_array().is_some_and(|events| {
                    events.iter().any(|e| e["event_type"] == "http.suspicious")
                }) =>
            {
                "Generación mock: solicitudes repetidas a rutas sensibles; verificar su procedencia y contexto sin asumir compromiso."
            }
            Some("R3") => {
                "Generación mock: errores de aplicación agrupados; revisar el contexto del servicio y sus dependencias."
            }
            _ => "Generación mock: patrón detectado; requiere revisión humana.",
        };
        let explanation = format!(
            "Se seleccionaron {} eventos del snapshot y se omitieron {}. Los hechos y la severidad proceden del detector. Las guías recuperadas permiten contrastar hipótesis; este patrón no confirma compromiso.",
            s["events"].as_array().map_or(0, Vec::len),
            s["omitted_count"].as_u64().unwrap_or(0)
        );
        json!({"schema_version":1,"summary":summary,"explanation":explanation,"evidence":s["events"].as_array().into_iter().flatten().take(5).map(|e|json!({"event_id":e["id"],"claim":match e["event_type"].as_str(){Some("auth.failed")=>"Credencial ficticia rechazada: fallo de autenticación observado.",Some("auth.success")=>"Acceso ficticio aceptado, incluido junto con los fallos previos.",Some("app.error")=>"Error del servicio ficticio registrado en la ventana observada.",_=>"Evento sintético incluido en el snapshot."}})).collect::<Vec<_>>(),"hypotheses":[{"text":"Posible repetición benigna de datos o configuración ficticia.","confidence":"low"}],"knowledge_references":refs,"decision_policy_refs":s["policies"].as_array().into_iter().flatten().map(|p|json!({"id":p["id"],"revision":p["revision"]})).collect::<Vec<_>>(),"uncertainty":["El patrón no confirma una intrusión."],"recommendations":["Revisar manualmente la secuencia y los datos faltantes."]})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_denies() {
        let p = json!([{ "definition":{"scope":["chat"],"rule_ids":["R1"],"event_types":[],"data_class":"synthetic","effect":"allow"}}]);
        assert!(policy_allows(&p, "chat", "R1", &[]));
        assert!(!policy_allows(&p, "chat", "R4", &[]));
        assert!(!policy_allows(&json!([]), "chat", "R1", &[]));
    }
    #[test]
    fn redact_canary() {
        let r = redact(
            "demo-user a@example.test Bearer canarytoken sk-123456789",
            "s",
        );
        assert!(!r.contains("canarytoken"));
        assert!(!r.contains("example.test"));
        assert!(!r.contains("demo-user"));
    }
    #[test]
    fn mock_claims_match_reference_events_and_never_assert_intrusion() {
        for (rule, kind, claim) in [
            ("R1", "auth.failed", "rechazada"),
            ("R2", "auth.success", "aceptado"),
            ("R3", "app.error", "Error del servicio"),
        ] {
            let id = Uuid::new_v4();
            let snapshot = json!({"rule_id":rule,"events":[{"id":id,"event_type":kind}],"chunks":[],"policies":[],"omitted_count":2});
            let response = mock_response("analysis", &snapshot);
            assert_eq!(response["evidence"][0]["event_id"], id.to_string());
            assert!(
                response["evidence"][0]["claim"]
                    .as_str()
                    .unwrap()
                    .contains(claim)
            );
            assert!(
                response["summary"]
                    .as_str()
                    .unwrap()
                    .starts_with("Generación mock:")
            );
            assert!(
                response["explanation"]
                    .as_str()
                    .unwrap()
                    .contains("se omitieron 2")
            );
            assert!(validate_response(response, "analysis", &snapshot).is_ok());
        }
    }
    #[test]
    fn hostile_output() {
        let s = json!({"events":[{"id":Uuid::nil(),"event_type":"auth.failed"}],"chunks":[],"policies":[]});
        let mut r = mock_response("analysis", &s);
        assert!(validate_response(r.clone(), "analysis", &s).is_ok());
        r["tool_calls"] = json!([]);
        let error = validate_response(r, "analysis", &s).unwrap_err();
        assert_eq!(validation_code(&error), "schema_unknown_field");
        let error = validate_response(json!({}), "chat", &s).unwrap_err();
        assert_eq!(validation_code(&error), "schema_missing_field");
        let mut r = mock_response("chat", &s);
        r["facts"][0]["event_ids"] = json!([Uuid::new_v4()]);
        assert!(validate_response(r, "chat", &s).is_err());
    }
}
#[cfg(test)]
mod derived_tests {
    use super::*;
    fn ssh_failed() -> Value {
        json!({
            "event_schema_version": 1,
            "event_type": "auth.failed",
            "source": "auth",
            "level": "warning",
            "timestamp": "2026-11-22T01:02:03Z",
            "timestamp_source": "syslog_context_year",
            "src_ip": "192.168.122.1",
            "username": "admin",
            "parser_name": "openssh-auth",
            "parser_version": "1",
            "attributes": {"auth_method": "password", "invalid_user": true, "protocol": "ssh"}
        })
    }
    fn validate(value: &Value) -> Result<DerivedValidation, DerivedIntegrityError> {
        validate_derived_events(value, "ssh", "openbsd:openssh", Some("9.9p1"))
    }
    #[test]
    fn valid_event_passes_with_attributes_and_timestamp() {
        let out = validate(&json!([ssh_failed()])).unwrap();
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.rejected, 0);
        assert!(!out.issues);
        let event = &out.events[0];
        assert_eq!(event.index, 0);
        assert_eq!(event.event_type, "auth.failed");
        assert_eq!(
            event.timestamp_source.as_deref(),
            Some("syslog_context_year")
        );
        assert_eq!(
            event.attributes.as_ref().unwrap()["auth_method"],
            json!("password")
        );
    }
    #[test]
    fn not_an_array_is_integrity() {
        assert_eq!(
            validate(&json!({"event_type": "auth.failed"})),
            Err(DerivedIntegrityError::NotArray)
        );
        assert_eq!(validate(&json!(null)), Err(DerivedIntegrityError::NotArray));
    }
    #[test]
    fn future_schema_and_unknown_shapes_are_enrichment() {
        let mut future = ssh_failed();
        future["event_schema_version"] = json!(2);
        let out = validate(&json!([future])).unwrap();
        assert!(out.events.is_empty() && out.rejected == 1 && out.issues);
        let mut unknown_type = ssh_failed();
        unknown_type["event_type"] = json!("auth.denied");
        assert!(validate(&json!([unknown_type])).unwrap().events.is_empty());
        let mut mismatch = ssh_failed();
        mismatch["source"] = json!("app");
        assert!(validate(&json!([mismatch])).unwrap().events.is_empty());
        let mut forbidden = ssh_failed();
        forbidden["message"] = json!("texto del adaptador");
        assert!(validate(&json!([forbidden])).unwrap().events.is_empty());
        let mut bad_level = ssh_failed();
        bad_level["level"] = json!("critical");
        assert!(validate(&json!([bad_level])).unwrap().events.is_empty());
    }
    #[test]
    fn identity_fields_distinguish_spoofing_from_redundant() {
        let mut spoofed = ssh_failed();
        spoofed["service"] = json!("mysql");
        assert_eq!(
            validate(&json!([spoofed])),
            Err(DerivedIntegrityError::IdentityMismatch)
        );
        let mut other_product = ssh_failed();
        other_product["product"] = json!("oracle:mysql");
        assert_eq!(
            validate(&json!([other_product])),
            Err(DerivedIntegrityError::IdentityMismatch)
        );
        let mut other_version = ssh_failed();
        other_version["version"] = json!("8.7");
        assert_eq!(
            validate(&json!([other_version])),
            Err(DerivedIntegrityError::IdentityMismatch)
        );
        // El campo con el valor correcto sobra igual: enriquecimiento.
        let mut redundant = ssh_failed();
        redundant["service"] = json!("ssh");
        let out = validate(&json!([redundant])).unwrap();
        assert!(out.events.is_empty() && out.rejected == 1);
        // Sin versión publicada por la fuente, reclamar una es suplantación.
        let mut claimed = ssh_failed();
        claimed["version"] = json!("9.9p1");
        assert_eq!(
            validate_derived_events(&json!([claimed]), "ssh", "openbsd:openssh", None),
            Err(DerivedIntegrityError::IdentityMismatch)
        );
    }
    #[test]
    fn type_minimums_are_enforced() {
        let mut no_ip = ssh_failed();
        no_ip.as_object_mut().unwrap().remove("src_ip");
        assert!(validate(&json!([no_ip])).unwrap().events.is_empty());
        let mut no_user = ssh_failed();
        no_user.as_object_mut().unwrap().remove("username");
        assert!(validate(&json!([no_user])).unwrap().events.is_empty());
        let mut bad_ip = ssh_failed();
        bad_ip["src_ip"] = json!("no-es-una-ip");
        assert!(validate(&json!([bad_ip])).unwrap().events.is_empty());
        let mut v6 = ssh_failed();
        v6["src_ip"] = json!("2001:db8::10");
        let out = validate(&json!([v6])).unwrap();
        assert_eq!(out.events[0].src_ip.as_deref(), Some("2001:db8::10"));
        let suspicious = json!({
            "event_schema_version": 1, "event_type": "http.suspicious", "source": "app",
            "level": "warning", "parser_name": "nginx-access", "parser_version": "1"
        });
        assert!(validate(&json!([suspicious])).unwrap().events.is_empty());
    }
    #[test]
    fn bad_timestamp_is_dropped_not_the_event() {
        let mut bad = ssh_failed();
        bad["timestamp"] = json!("ayer a la noche");
        let out = validate(&json!([bad])).unwrap();
        assert_eq!(out.events.len(), 1);
        assert!(out.events[0].timestamp.is_none());
        assert!(out.issues);
        let mut no_source = ssh_failed();
        no_source
            .as_object_mut()
            .unwrap()
            .remove("timestamp_source");
        let out = validate(&json!([no_source])).unwrap();
        assert_eq!(out.events.len(), 1);
        assert!(out.events[0].timestamp.is_none());
        assert!(out.issues);
        let mut orphan_source = ssh_failed();
        orphan_source.as_object_mut().unwrap().remove("timestamp");
        assert!(validate(&json!([orphan_source])).unwrap().events.is_empty());
    }
    #[test]
    fn attributes_are_a_closed_bounded_set() {
        let mut unknown_key = ssh_failed();
        unknown_key["attributes"] = json!({"password": "nope"});
        assert!(validate(&json!([unknown_key])).unwrap().events.is_empty());
        let mut all_keys = ssh_failed();
        all_keys["attributes"] = json!({
            "auth_method": "password", "invalid_user": false, "protocol": "ssh",
            "request_id": "r-1", "session_id": "s-1", "upstream_status": 502,
            "db_user": "root", "error_code": "MY-1", "operation": "connect"
        });
        // Nueve claves permitidas pero el máximo es ocho.
        assert!(validate(&json!([all_keys])).unwrap().events.is_empty());
        let mut bad_status = ssh_failed();
        bad_status["attributes"] = json!({"upstream_status": 99});
        assert!(validate(&json!([bad_status])).unwrap().events.is_empty());
        let mut bad_method = ssh_failed();
        bad_method["attributes"] = json!({"auth_method": "token"});
        assert!(validate(&json!([bad_method])).unwrap().events.is_empty());
        let mut long_request = ssh_failed();
        long_request["attributes"] = json!({"request_id": "x".repeat(65)});
        assert!(validate(&json!([long_request])).unwrap().events.is_empty());
    }
    #[test]
    fn duplicates_and_cap_keep_first_four_valid() {
        let out = validate(&json!([ssh_failed(), ssh_failed()])).unwrap();
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.rejected, 1);
        let mut batch = Vec::new();
        for n in 0..6 {
            let mut event = ssh_failed();
            event["username"] = json!(format!("user{n}"));
            batch.push(event);
        }
        let out = validate(&Value::Array(batch)).unwrap();
        assert_eq!(out.events.len(), DERIVED_MAX_EVENTS_PER_RECORD);
        assert_eq!(out.rejected, 2);
        assert!(out.issues);
        // El índice conservado es el del array original, no el de aceptados.
        assert_eq!(out.events[3].index, 3);
    }
    #[test]
    fn oversized_event_is_rejected_before_field_rules() {
        // El tamaño serializado se comprueba antes que cualquier otra regla:
        // un timestamp de 5 000 caracteres ya supera los 4 KiB del evento.
        let mut huge = ssh_failed();
        huge["timestamp"] = json!("x".repeat(5000));
        let out = validate(&json!([huge])).unwrap();
        assert!(out.events.is_empty() && out.rejected == 1 && out.issues);
    }
    #[test]
    fn derived_identity_is_stable_and_position_sensitive() {
        let record = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"record-fixture");
        let a = derived_event_id(&record, "openssh-auth", "1", 0);
        assert_eq!(a, derived_event_id(&record, "openssh-auth", "1", 0));
        assert_ne!(a, derived_event_id(&record, "openssh-auth", "1", 1));
        assert_ne!(a, derived_event_id(&record, "openssh-auth", "2", 0));
        assert_ne!(a, derived_event_id(&record, "nginx-access", "1", 0));
    }
}

#[cfg(test)]
mod unicode_tests {
    use super::*;
    #[test]
    fn utf8_and_synthetic_identity() {
        let mut v = json!({"schema_version":1,"scenario_run_id":Uuid::new_v4(),"event_id":Uuid::new_v4(),"seq":1,"timestamp":"2026-11-12T12:00:00Z","source":"system","event_type":"system.notice","level":"info","message":"Año sintético: ñ","user":"demo-unicode","src_ip":"192.0.2.10"});
        assert_eq!(
            parse_line(v.to_string().as_bytes()).unwrap().message,
            "Año sintético: ñ"
        );
        v["src_ip"] = json!("10.0.0.1");
        assert!(parse_line(v.to_string().as_bytes()).is_err());
        v["src_ip"] = json!("192.0.2.10");
        v["user"] = json!("real-person");
        assert!(parse_line(v.to_string().as_bytes()).is_err());
    }
}
