use crate::{App, api::ApiError, db, hash};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

type Result<T> = std::result::Result<T, ApiError>;
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
}
fn conflict() -> ApiError {
    ApiError(StatusCode::CONFLICT, "conflict")
}
fn uuid(v: &Value, key: &str) -> Result<Uuid> {
    v[key]
        .as_str()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())
}
fn fields(v: &Value, allowed: &[&str]) -> Result<()> {
    let o = v.as_object().ok_or_else(invalid)?;
    if o.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid());
    }
    Ok(())
}
fn text(v: &Value, key: &str, max_chars: usize, max_bytes: usize) -> Result<String> {
    let s = v[key].as_str().ok_or_else(invalid)?.trim();
    if s.chars().count() > max_chars || s.len() > max_bytes || s.contains('\0') {
        return Err(invalid());
    }
    Ok(s.to_owned())
}
fn boolean(v: &Value, key: &str, default: bool) -> Result<bool> {
    match v.get(key) {
        None => Ok(default),
        Some(x) => x.as_bool().ok_or_else(invalid),
    }
}
pub async fn lock(tx: &mut Transaction<'_, Postgres>) -> std::result::Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(7616)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}
pub fn validate_config(kind: &str, v: &Value) -> Result<()> {
    match kind {
        "folder" => {
            fields(
                v,
                &["root_alias", "directory", "selector", "data_class", "year"],
            )?;
            if let Some(directory) = v.get("directory") {
                let directory = directory.as_str().ok_or_else(invalid)?;
                if directory.len() > 64
                    || !directory
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                {
                    return Err(invalid());
                }
            }
            match v["root_alias"].as_str() {
                Some("demo-logs")
                    if v.get("data_class").is_none_or(|x| x == "synthetic")
                        && v.get("year").is_none() => {}
                Some("external")
                    if v["data_class"] == "real"
                        && v.get("year").is_none_or(|y| {
                            y.as_i64().is_some_and(|n| (1970..=2100).contains(&n))
                        }) => {}
                _ => return Err(invalid()),
            }
            let selector = v["selector"].as_str().ok_or_else(invalid)?;
            if selector.is_empty()
                || selector.len() > 255
                || selector.contains(['/', '\\', '\0'])
                || selector.contains("..")
                || !selector
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-*".contains(c))
                || selector.matches('*').count() > 1
                || !(selector.ends_with(".log") || selector.ends_with(".ndjson"))
            {
                return Err(invalid());
            }
        }
        "mcp" => {
            fields(
                v,
                &[
                    "endpoint",
                    "resource_uri",
                    "synthetic",
                    "mode",
                    "poll_seconds",
                    "ca_pem",
                ],
            )?;
            let endpoint = v["endpoint"].as_str().ok_or_else(invalid)?;
            let uri = v["resource_uri"].as_str().ok_or_else(invalid)?;
            if v["mode"] == "incremental_lab" {
                if v["synthetic"] != false
                    || crate::mcp::lab_resource(uri).is_none()
                    || !v["poll_seconds"]
                        .as_u64()
                        .is_some_and(|n| (5..=300).contains(&n))
                    || crate::mcp::lab_endpoint_shape(endpoint).is_err()
                {
                    return Err(invalid());
                }
                if let Some(ca) = v.get("ca_pem") {
                    if let Some(pem) = ca.as_str() {
                        if !pem.is_empty()
                            && (pem.len() > 16384
                                || reqwest::Certificate::from_pem(pem.as_bytes()).is_err())
                        {
                            return Err(invalid());
                        }
                    } else if !ca.is_null() {
                        return Err(invalid());
                    }
                }
            } else {
                if v["synthetic"] != true
                    || v.get("mode").is_some()
                    || v.get("poll_seconds").is_some()
                    || v.get("ca_pem").is_some()
                {
                    return Err(invalid());
                }
                crate::mcp::validate_endpoint(endpoint).map_err(|_| invalid())?;
            }
            if uri.is_empty() || uri.len() > 2048 || uri.contains(['\0', '\r', '\n']) {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}
/// Señales cerradas que una regla específica del operador puede contar.
/// Una regla «custom:<slug>» es un contador genérico por fuente: cuenta los
/// eventos de su fuente que coinciden con la señal dentro de la ventana y
/// abre una incidencia al llegar al umbral, con su nombre y severidad.
pub const CUSTOM_SIGNALS: [&str; 6] = [
    "auth.failed",
    "auth.success",
    "app.error",
    "http.suspicious",
    "level.error",
    "any",
];
pub fn custom_signal_matches(signal: &str, event_type: &str, level: &str) -> bool {
    match signal {
        "any" => true,
        "level.error" => level == "error",
        "auth.failed" | "auth.success" | "app.error" | "http.suspicious" => signal == event_type,
        _ => false,
    }
}

pub fn validate_analysis(v: &Value) -> Result<()> {
    fields(v, &["system", "protocol", "adapter", "context", "rules"])?;
    for key in ["system", "protocol"] {
        let value = text(v, key, 80, 160)?;
        if value.is_empty() {
            return Err(invalid());
        }
    }
    if !["auto", "sentinel-json", "native-text", "plain-text"]
        .contains(&v["adapter"].as_str().ok_or_else(invalid)?)
    {
        return Err(invalid());
    }
    text(v, "context", 2000, 4096)?;
    let rules = v["rules"].as_array().ok_or_else(invalid)?;
    // R1–R3, las cinco plantillas de observabilidad (OBS-01) y las reglas
    // específicas del operador («custom:…»): máximo 12 por fuente.
    if rules.len() > 12 {
        return Err(invalid());
    }
    let mut seen = std::collections::HashSet::new();
    for rule in rules {
        let id = rule["id"].as_str().ok_or_else(invalid)?;
        let is_template = crate::observability::TEMPLATES
            .iter()
            .any(|(t, _, _, _, _)| *t == id);
        if is_template {
            // Plantillas de observabilidad: mismo modelo cerrado que R1–R3
            // (enabled/threshold/window) más severidad inicial de lista
            // cerrada; sin condición ni campos libres.
            fields(
                rule,
                &["id", "enabled", "threshold", "window_seconds", "severity"],
            )?;
            if !seen.insert(id)
                || !rule["enabled"].is_boolean()
                || !rule["threshold"]
                    .as_u64()
                    .is_some_and(|n| (1..=100).contains(&n))
                || !rule["window_seconds"]
                    .as_u64()
                    .is_some_and(|n| (1..=600).contains(&n))
                || rule.get("severity").is_some_and(|sev| {
                    !["low", "medium", "high", "critical"].contains(&sev.as_str().unwrap_or(""))
                })
            {
                return Err(invalid());
            }
            continue;
        }
        if let Some(slug) = id.strip_prefix("custom:") {
            // Regla específica del operador: nombre propio, señal cerrada,
            // umbral/ventana como el resto y severidad obligatoria de la
            // lista cerrada; sin condición ni campos libres.
            fields(
                rule,
                &[
                    "id",
                    "name",
                    "signal",
                    "enabled",
                    "threshold",
                    "window_seconds",
                    "severity",
                ],
            )?;
            if !seen.insert(id)
                || slug.is_empty()
                || slug.len() > 40
                || !slug
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || text(rule, "name", 80, 160)?.is_empty()
                || !CUSTOM_SIGNALS.contains(&rule["signal"].as_str().ok_or_else(invalid)?)
                || !rule["enabled"].is_boolean()
                || !rule["threshold"]
                    .as_u64()
                    .is_some_and(|n| (1..=100).contains(&n))
                || !rule["window_seconds"]
                    .as_u64()
                    .is_some_and(|n| (1..=600).contains(&n))
                || !["low", "medium", "high", "critical"]
                    .contains(&rule["severity"].as_str().ok_or_else(invalid)?)
            {
                return Err(invalid());
            }
            continue;
        }
        fields(
            rule,
            &["id", "enabled", "threshold", "window_seconds", "condition"],
        )?;
        if !["R1", "R2", "R3"].contains(&id)
            || !seen.insert(id)
            || !rule["enabled"].is_boolean()
            || !rule["threshold"]
                .as_u64()
                .is_some_and(|n| (1..=100).contains(&n))
            || !rule["window_seconds"]
                .as_u64()
                .is_some_and(|n| (1..=600).contains(&n))
        {
            return Err(invalid());
        }
        if let Some(condition) = rule.get("condition") {
            fields(condition, &["field", "operator", "value"])?;
            if !["level", "source"].contains(&condition["field"].as_str().ok_or_else(invalid)?)
                || !["eq", "not_eq"].contains(&condition["operator"].as_str().ok_or_else(invalid)?)
                || text(condition, "value", 80, 160)?.is_empty()
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

/// Compatibilidad cerrada entre una plantilla de observabilidad y el tipo de
/// fuente: devuelve None si la plantilla puede habilitarse en esa fuente o
/// el motivo (en español, para la UI) si no. Las plantillas HTTP se evalúan
/// solo cuando los eventos traen evidencia HTTP; las de estructura solo
/// tienen sentido en las fuentes de carpeta que respaldan las raíces del
/// mapa de estructura.
pub fn template_compatibility(kind: &str, template_id: &str) -> Option<&'static str> {
    match template_id {
        "request_outside_declared_surface"
        | "encoded_path_traversal"
        | "ambiguous_request_normalization" => None,
        "unexpected_structure_change" | "sensitive_structure_change" => {
            if kind == "folder" {
                None
            } else {
                Some(
                    "las plantillas de estructura se configuran en las fuentes de carpeta que respaldan las raíces del mapa de estructura (demo-logs/external); esta fuente no respalda rutas del filesystem",
                )
            }
        }
        _ => Some("plantilla desconocida"),
    }
}

pub fn validate_template_compatibility(kind: &str, v: &Value) -> Result<()> {
    for rule in v["rules"].as_array().cloned().unwrap_or_default() {
        let id = rule["id"].as_str().unwrap_or("");
        if crate::observability::TEMPLATES
            .iter()
            .any(|(t, _, _, _, _)| *t == id)
            && template_compatibility(kind, id).is_some()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub fn inspect_sample(sample: &str) -> Value {
    let first = sample
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    match serde_json::from_str::<Value>(first) {
        Ok(Value::Object(object)) => {
            json!({"format":"json","fields":object.keys().take(32).collect::<Vec<_>>(),"diagnostic":null})
        }
        _ => json!({"format":"plain-text","fields":[],"diagnostic":"sin_proyeccion_estructurada"}),
    }
}
pub fn condition_matches(condition: &Value, level: &str, source: &str) -> bool {
    let actual = match condition["field"].as_str() {
        Some("level") => level,
        Some("source") => source,
        _ => return false,
    };
    match condition["operator"].as_str() {
        Some("eq") => actual == condition["value"].as_str().unwrap_or(""),
        Some("not_eq") => actual != condition["value"].as_str().unwrap_or(""),
        _ => false,
    }
}
pub fn selector_matches(selector: &str, name: &str) -> bool {
    match selector.split_once('*') {
        Some((prefix, suffix)) => {
            name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
        }
        None => selector == name,
    }
}
fn selectors_overlap(a: &str, b: &str) -> bool {
    match (a.split_once('*'), b.split_once('*')) {
        (Some((ap, asuffix)), Some((bp, bsuffix))) => {
            (ap.starts_with(bp) || bp.starts_with(ap))
                && (asuffix.ends_with(bsuffix) || bsuffix.ends_with(asuffix))
        }
        (Some(_), None) => selector_matches(a, b),
        (None, Some(_)) => selector_matches(b, a),
        (None, None) => a == b,
    }
}
async fn unique_source(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    kind: &str,
    config: &Value,
) -> Result<()> {
    let rows=sqlx::query("SELECT kind,config FROM sources WHERE id<>$1 AND deleted_at IS NULL AND service_id IS NOT NULL").bind(id).fetch_all(&mut **tx).await?;
    for r in rows {
        let other_kind: String = r.get("kind");
        let other: Value = r.get("config");
        let overlaps = if kind == "folder" && other_kind == "folder" {
            config["root_alias"] == other["root_alias"]
                && config["directory"].as_str().unwrap_or("")
                    == other["directory"].as_str().unwrap_or("")
                && selectors_overlap(
                    config["selector"].as_str().unwrap_or(""),
                    other["selector"].as_str().unwrap_or(""),
                )
        } else {
            kind == "mcp"
                && other_kind == "mcp"
                && config["endpoint"] == other["endpoint"]
                && config["resource_uri"] == other["resource_uri"]
        };
        if overlaps {
            return Err(conflict());
        }
    }
    Ok(())
}
fn cursor(q: &HashMap<String, String>, scope: &str) -> Result<(i64, Option<(String, Uuid)>)> {
    if q.keys().any(|k| {
        ![
            "q",
            "state",
            "source_kind",
            "system",
            "protocol",
            "source_state",
            "cursor",
            "limit",
        ]
        .contains(&k.as_str())
    }) {
        return Err(invalid());
    }
    let limit = q
        .get("limit")
        .map(|s| s.parse::<i64>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(25);
    if !(1..=100).contains(&limit)
        || q.get("q").is_some_and(|s| s.chars().count() > 128)
        || q.get("state")
            .is_some_and(|s| !["active", "inactive", "deleted", "all"].contains(&s.as_str()))
        || q.get("source_kind")
            .is_some_and(|s| !["folder", "mcp"].contains(&s.as_str()))
        || ["system", "protocol"]
            .iter()
            .any(|key| q.get(*key).is_some_and(|s| s.chars().count() > 80))
        || q.get("source_state").is_some_and(|s| {
            ![
                "active", "inactive", "healthy", "degraded", "blocked", "pending",
            ]
            .contains(&s.as_str())
        })
    {
        return Err(invalid());
    }
    let at = q
        .get("cursor")
        .map(|c| {
            let v: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(c).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
            if v["filters"] != filter_hash(q, scope) {
                return Err(invalid());
            }
            Ok((
                v["name"].as_str().ok_or_else(invalid)?.to_owned(),
                uuid(&v, "id")?,
            ))
        })
        .transpose()?;
    Ok((limit, at))
}
fn filter_hash(q: &HashMap<String, String>, scope: &str) -> String {
    let mut filters = q
        .iter()
        .filter(|(k, _)| k.as_str() != "cursor")
        .collect::<Vec<_>>();
    filters.sort();
    hash(format!("{scope}:{filters:?}"))
}
fn encode(q: &HashMap<String, String>, scope: &str, name: &str, id: &Value) -> String {
    URL_SAFE_NO_PAD.encode(json!({"name":name,"id":id,"filters":filter_hash(q,scope)}).to_string())
}
const SERVICE_FIELDS: &str = "to_jsonb(s)||jsonb_build_object('context',coalesce(r.context,''),'source_count',(SELECT count(*) FROM sources x WHERE x.service_id=s.id AND x.deleted_at IS NULL),'source_kinds',(SELECT coalesce(jsonb_agg(DISTINCT kind),'[]') FROM sources x WHERE x.service_id=s.id AND x.deleted_at IS NULL),'status',CASE WHEN s.deleted_at IS NOT NULL THEN 'deleted' WHEN NOT s.enabled THEN 'inactive' WHEN EXISTS(SELECT 1 FROM sources x WHERE x.service_id=s.id AND x.enabled AND x.deleted_at IS NULL AND x.status<>'healthy') THEN 'degraded' ELSE 'healthy' END,'last_received_at',(SELECT max(received_at) FROM text_records t WHERE t.service_id=s.id),'cve_affecting',(SELECT c.affecting_count FROM cve_checks c WHERE c.service_id=s.id AND c.state='completed' ORDER BY c.checked_at DESC,c.id DESC LIMIT 1),'cve_checked_at',(SELECT c.checked_at FROM cve_checks c WHERE c.service_id=s.id AND c.state='completed' ORDER BY c.checked_at DESC,c.id DESC LIMIT 1))";
const SOURCE_FIELDS: &str = "to_jsonb(x)||jsonb_build_object('has_credential',EXISTS(SELECT 1 FROM source_credentials c WHERE c.source_id=x.id),'last_check',(SELECT to_jsonb(c) FROM source_checks c WHERE c.source_id=x.id),'lag_bytes',(SELECT coalesce(sum(c.last_size-c.committed_offset),0) FROM source_cursors c JOIN file_instances f ON f.id=c.file_instance_id WHERE f.source_id=x.id),'errors',(SELECT count(*) FROM ingestion_errors e WHERE e.source_id=x.id))";
pub async fn list(app: &App, q: &HashMap<String, String>) -> Result<Value> {
    let (limit, at) = cursor(q, "services")?;
    let filter = "($1::text IS NULL OR position(lower($1) in lower(s.name))>0) AND (CASE coalesce($2::text,'current') WHEN 'active' THEN s.enabled AND s.deleted_at IS NULL WHEN 'inactive' THEN NOT s.enabled AND s.deleted_at IS NULL WHEN 'deleted' THEN s.deleted_at IS NOT NULL WHEN 'all' THEN true ELSE s.deleted_at IS NULL END) AND ($3::text IS NULL OR EXISTS(SELECT 1 FROM sources x WHERE x.service_id=s.id AND x.kind=$3 AND x.deleted_at IS NULL)) AND ($4::text IS NULL OR EXISTS(SELECT 1 FROM sources x WHERE x.service_id=s.id AND lower(x.analysis->>'system')=lower($4) AND x.deleted_at IS NULL)) AND ($5::text IS NULL OR EXISTS(SELECT 1 FROM sources x WHERE x.service_id=s.id AND lower(x.analysis->>'protocol')=lower($5) AND x.deleted_at IS NULL)) AND ($6::text IS NULL OR EXISTS(SELECT 1 FROM sources x WHERE x.service_id=s.id AND x.deleted_at IS NULL AND (CASE $6 WHEN 'active' THEN x.enabled WHEN 'inactive' THEN NOT x.enabled ELSE x.status=$6 END)))";
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM services s WHERE {filter}"))
        .bind(q.get("q"))
        .bind(q.get("state"))
        .bind(q.get("source_kind"))
        .bind(q.get("system"))
        .bind(q.get("protocol"))
        .bind(q.get("source_state"))
        .fetch_one(&app.pool)
        .await?;
    let mut rows:Vec<Value>=sqlx::query_scalar(&format!("SELECT {SERVICE_FIELDS} FROM services s LEFT JOIN service_revisions r ON r.service_id=s.id AND r.version=s.version WHERE {filter} AND ($7::text IS NULL OR (lower(s.name),s.id)>($7,$8)) ORDER BY lower(s.name),s.id LIMIT $9")).bind(q.get("q")).bind(q.get("state")).bind(q.get("source_kind")).bind(q.get("system")).bind(q.get("protocol")).bind(q.get("source_state")).bind(at.as_ref().map(|x|&x.0)).bind(at.as_ref().map(|x|x.1)).bind(limit+1).fetch_all(&app.pool).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().map(|r| {
            encode(
                q,
                "services",
                &r["name"].as_str().unwrap_or("").to_lowercase(),
                &r["id"],
            )
        })
    } else {
        None
    };
    Ok(
        json!({"items":rows,"total_count":total,"next_cursor":next,"unassigned_records":sqlx::query_scalar::<_,i64>("SELECT count(*) FROM text_records WHERE service_id IS NULL").fetch_one(&app.pool).await?,"unresolved_rules":sqlx::query_scalar::<_,i64>("SELECT count(*) FROM unresolved_service_rules").fetch_one(&app.pool).await?}),
    )
}
pub async fn detail(app: &App, id: Uuid) -> Result<Value> {
    let mut row:Value=sqlx::query_scalar(&format!("SELECT {SERVICE_FIELDS} FROM services s LEFT JOIN service_revisions r ON r.service_id=s.id AND r.version=s.version WHERE s.id=$1")).bind(id).fetch_one(&app.pool).await?;
    row["sources"] = source_list(app, id, &HashMap::new()).await?;
    row["dependencies"]=sqlx::query_scalar("SELECT jsonb_build_object('records',(SELECT count(*) FROM text_records WHERE service_id=$1),'incidents',(SELECT count(*) FROM incident_services WHERE service_id=$1),'in_flight',(SELECT count(*) FROM analysis_jobs j WHERE j.state IN('reserved','in_flight') AND (EXISTS(SELECT 1 FROM incident_services i WHERE i.incident_id=j.incident_id AND i.service_id=$1) OR EXISTS(SELECT 1 FROM review_segments rs JOIN text_records tr ON tr.id=rs.record_id WHERE rs.job_id=j.id AND tr.service_id=$1))))").bind(id).fetch_one(&app.pool).await?;
    Ok(row)
}
pub async fn source_list(app: &App, id: Uuid, q: &HashMap<String, String>) -> Result<Value> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM services WHERE id=$1)")
        .bind(id)
        .fetch_one(&app.pool)
        .await?;
    if !exists {
        return Err(ApiError(StatusCode::NOT_FOUND, "not_found"));
    }
    sources_page(app, Some(id), q).await
}
pub async fn all_sources(app: &App, q: &HashMap<String, String>) -> Result<Value> {
    sources_page(app, None, q).await
}
async fn sources_page(app: &App, id: Option<Uuid>, q: &HashMap<String, String>) -> Result<Value> {
    if q.keys().any(|k| !["cursor", "limit"].contains(&k.as_str())) {
        return Err(invalid());
    }
    let scope = format!("sources/{id:?}");
    let (limit, at) = cursor(q, &scope)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sources WHERE ($1::uuid IS NULL OR service_id=$1) AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(&app.pool)
    .await?;
    let mut rows:Vec<Value>=sqlx::query_scalar(&format!("SELECT {SOURCE_FIELDS} FROM sources x WHERE ($1::uuid IS NULL OR x.service_id=$1) AND x.deleted_at IS NULL AND ($2::text IS NULL OR (x.logical_name,x.id)>($2,$3)) ORDER BY x.logical_name,x.id LIMIT $4")).bind(id).bind(at.as_ref().map(|x|&x.0)).bind(at.as_ref().map(|x|x.1)).bind(limit+1).fetch_all(&app.pool).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().map(|r| {
            encode(
                q,
                &scope,
                r["logical_name"].as_str().unwrap_or(""),
                &r["id"],
            )
        })
    } else {
        None
    };
    Ok(json!({"items":rows,"total_count":total,"next_cursor":next}))
}
pub async fn source_detail(app: &App, id: Uuid) -> Result<Value> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT {SOURCE_FIELDS} FROM sources x WHERE x.id=$1"
    ))
    .bind(id)
    .fetch_one(&app.pool)
    .await?)
}
pub async fn preview_rules(app: &App, id: Uuid) -> Result<Value> {
    let analysis: Value =
        sqlx::query_scalar("SELECT analysis FROM sources WHERE id=$1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_one(&app.pool)
            .await?;
    let events = sqlx::query("SELECT id,run_id,ingest_seq,ingested_at,event_type,level,source,src_ip,user_alias,service FROM events WHERE source_id=$1 ORDER BY ingest_seq DESC LIMIT 500")
        .bind(id).fetch_all(&app.pool).await?;
    let mut results = Vec::new();
    for rule in analysis["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["enabled"] == true)
    {
        let rule_id = rule["id"].as_str().unwrap_or("");
        let window = chrono::Duration::seconds(rule["window_seconds"].as_i64().unwrap_or(0));
        let threshold = rule["threshold"].as_u64().unwrap_or(u64::MAX) as usize;
        let condition = rule.get("condition");
        let mut matches = Vec::new();
        let mut match_count = 0;
        let mut candidates = 0;
        for event in &events {
            let event_type: String = event.get("event_type");
            let level: String = event.get("level");
            let is_custom = rule_id.starts_with("custom:");
            if !(if is_custom {
                custom_signal_matches(rule["signal"].as_str().unwrap_or(""), &event_type, &level)
            } else {
                match rule_id {
                    "R1" => event_type == "auth.failed",
                    "R2" => event_type == "auth.success",
                    "R3" => matches!(event_type.as_str(), "app.error" | "http.suspicious"),
                    _ => false,
                }
            }) {
                continue;
            }
            let source: String = event.get("source");
            if condition.is_some_and(|c| !condition_matches(c, &level, &source)) {
                continue;
            }
            let ip: Option<String> = event.get("src_ip");
            let user: Option<String> = event.get("user_alias");
            let service: Option<String> = event.get("service");
            if service.is_none()
                || (matches!(rule_id, "R1" | "R2") && (ip.is_none() || user.is_none()))
                || (event_type == "http.suspicious" && ip.is_none() && !is_custom)
            {
                continue;
            }
            candidates += 1;
            let time: chrono::DateTime<chrono::Utc> = event.get("ingested_at");
            let seq: i64 = event.get("ingest_seq");
            let run: Uuid = event.get("run_id");
            let count = events
                .iter()
                .filter(|prior| {
                    let prior_time: chrono::DateTime<chrono::Utc> = prior.get("ingested_at");
                    let prior_type: String = prior.get("event_type");
                    let prior_level: String = prior.get("level");
                    let prior_source: String = prior.get("source");
                    prior.get::<Uuid, _>("run_id") == run
                        && prior.get::<i64, _>("ingest_seq") <= seq
                        && prior_time >= time - window
                        && prior_time <= time
                        && (if is_custom {
                            custom_signal_matches(
                                rule["signal"].as_str().unwrap_or(""),
                                &prior_type,
                                &prior_level,
                            )
                        } else {
                            prior_type
                                == if rule_id == "R2" {
                                    "auth.failed"
                                } else {
                                    event_type.as_str()
                                }
                                && (rule_id == "R3" && event_type != "http.suspicious"
                                    || prior.get::<Option<String>, _>("src_ip") == ip)
                                && (rule_id == "R3"
                                    || prior.get::<Option<String>, _>("user_alias") == user)
                        })
                        && condition
                            .is_none_or(|c| condition_matches(c, &prior_level, &prior_source))
                })
                .count();
            if count >= threshold {
                match_count += 1;
                if matches.len() < 20 {
                    matches
                        .push(json!({"event_id":event.get::<Uuid,_>("id"),"evidence_count":count}));
                }
            }
        }
        results.push(json!({"rule_id":rule_id,"name":rule.get("name").cloned().unwrap_or(Value::Null),"candidates":candidates,"match_count":match_count,"matches":matches,"threshold":threshold,"window_seconds":window.num_seconds()}));
    }
    Ok(
        json!({"source_id":id,"inspected_events":events.len(),"limited":events.len()==500,"rules":results,"note":"Vista previa de los últimos 500 eventos; no crea incidencias ni llama a la IA."}),
    )
}
pub async fn source_history(app: &App, id: Uuid, q: &HashMap<String, String>) -> Result<Value> {
    if q.keys()
        .any(|key| !["limit", "before"].contains(&key.as_str()))
    {
        return Err(invalid());
    }
    let limit = q
        .get("limit")
        .map(|value| value.parse::<i64>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(20);
    let before = q
        .get("before")
        .map(|value| value.parse::<i32>().map_err(|_| invalid()))
        .transpose()?;
    if !(1..=100).contains(&limit) || before.is_some_and(|v| v < 1) {
        return Err(invalid());
    }
    let mut rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('version',version,'analysis',analysis,'created_at',created_at) FROM source_revisions WHERE source_id=$1 AND ($2::int IS NULL OR version<$2) ORDER BY version DESC LIMIT $3")
        .bind(id).bind(before).bind(limit+1).fetch_all(&app.pool).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().and_then(|row| row["version"].as_i64())
    } else {
        None
    };
    Ok(json!({"items":rows,"next_before":next}))
}
pub async fn restore_source_analysis(app: &App, id: Uuid, v: &Value) -> Result<Value> {
    fields(v, &["expected_version", "restore_version"])?;
    let restore_version = v["restore_version"].as_i64().ok_or_else(invalid)?;
    if restore_version < 1 || restore_version > i32::MAX as i64 {
        return Err(invalid());
    }
    let analysis: Value = sqlx::query_scalar(
        "SELECT analysis FROM source_revisions WHERE source_id=$1 AND version=$2",
    )
    .bind(id)
    .bind(restore_version as i32)
    .fetch_one(&app.pool)
    .await?;
    update_source(
        app,
        id,
        &json!({"expected_version":v["expected_version"],"analysis":analysis}),
        false,
    )
    .await
}
async fn revision(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    version: i32,
    name: &str,
    description: &str,
    context: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO service_revisions(service_id,version,name,description,context,context_hash) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(version).bind(name).bind(description).bind(context).bind(hash(context)).execute(&mut **tx).await?;
    Ok(())
}
async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    kind: &str,
    key: Uuid,
    payload: &str,
) -> Result<Option<Uuid>> {
    let old = sqlx::query(
        "SELECT payload_hash,resource_id FROM service_requests WHERE kind=$1 AND key=$2",
    )
    .bind(kind)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = old {
        if row.get::<String, _>("payload_hash") != payload {
            return Err(conflict());
        }
        return Ok(Some(row.get("resource_id")));
    }
    Ok(None)
}
async fn remember(
    tx: &mut Transaction<'_, Postgres>,
    kind: &str,
    key: Uuid,
    payload: &str,
    id: Uuid,
) -> Result<()> {
    sqlx::query("INSERT INTO service_requests VALUES($1,$2,$3,$4)")
        .bind(kind)
        .bind(key)
        .bind(payload)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn save_credential(
    app: &App,
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    v: &Value,
) -> Result<()> {
    if let Some(value) = v.get("credential") {
        let secret = value.as_str().ok_or_else(invalid)?;
        if secret.is_empty() || secret.len() > 4096 || secret.contains(['\r', '\n']) {
            return Err(invalid());
        }
        let master = app.config.master_key.as_deref().ok_or_else(invalid)?;
        let (cipher, nonce) = crate::api::encrypt(master, secret)?;
        sqlx::query("INSERT INTO source_credentials VALUES($1,$2,$3) ON CONFLICT(source_id) DO UPDATE SET ciphertext=$2,nonce=$3").bind(id).bind(cipher).bind(nonce).execute(&mut **tx).await?;
    }
    Ok(())
}
async fn insert_source(
    app: &App,
    tx: &mut Transaction<'_, Postgres>,
    service: Uuid,
    v: &Value,
) -> Result<Uuid> {
    fields(
        v,
        &[
            "kind",
            "config",
            "analysis",
            "enabled",
            "idempotency_key",
            "credential",
        ],
    )?;
    let kind = v["kind"].as_str().ok_or_else(invalid)?;
    validate_config(kind, &v["config"])?;
    let analysis = v.get("analysis").cloned().unwrap_or_else(|| json!({"system":"Sin especificar","protocol":"Sin especificar","adapter":"auto","context":"","rules":[]}));
    validate_analysis(&analysis)?;
    validate_template_compatibility(kind, &analysis)?;
    let id = Uuid::new_v4();
    let enabled = boolean(v, "enabled", false)?;
    if enabled {
        return Err(invalid());
    }
    if kind != "mcp" && v.get("credential").is_some() {
        return Err(invalid());
    }
    unique_source(tx, id, kind, &v["config"]).await?;
    sqlx::query("INSERT INTO sources(id,logical_name,service_id,kind,enabled,config,data_class,analysis) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(id).bind(format!("source-{id}")).bind(service).bind(kind).bind(enabled).bind(&v["config"]).bind(if (kind == "folder" && v["config"]["root_alias"] == "external") || (kind == "mcp" && v["config"]["mode"] == "incremental_lab") { "real" } else { "synthetic" }).bind(&analysis).execute(&mut **tx).await?;
    sqlx::query(
        "INSERT INTO source_revisions(source_id,version,config,analysis) VALUES($1,1,$2,$3)",
    )
    .bind(id)
    .bind(&v["config"])
    .bind(&analysis)
    .execute(&mut **tx)
    .await?;
    save_credential(app, tx, id, v).await?;
    db::emit(tx, "source.updated", id, 1).await?;
    Ok(id)
}
pub async fn create(app: &App, v: &Value) -> Result<Value> {
    fields(
        v,
        &[
            "name",
            "description",
            "context",
            "enabled",
            "idempotency_key",
            "source",
            "software_product",
            "software_version",
        ],
    )?;
    let key = uuid(v, "idempotency_key")?;
    let name = text(v, "name", 128, 512)?;
    if name.is_empty() {
        return Err(invalid());
    }
    let description = text(v, "description", 2000, 4096)?;
    let context = text(v, "context", 4000, 8192)?;
    let enabled = boolean(v, "enabled", true)?;
    let software = crate::cve::declared_software(v)?;
    let payload = hash(v.to_string());
    let mut tx = app.pool.begin().await?;
    lock(&mut tx).await?;
    if let Some(id) = replay(&mut tx, "service", key, &payload).await? {
        tx.commit().await?;
        return detail(app, id).await;
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO services(id,name,description,enabled,software_product,software_version,software_origin) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(enabled)
        .bind(software.as_ref().map(|(p, _)| p.clone()))
        .bind(software.as_ref().map(|(_, ver)| ver.clone()))
        .bind(software.as_ref().map(|_| "operator"))
        .execute(&mut *tx)
        .await?;
    revision(&mut tx, id, 1, &name, &description, &context).await?;
    if let Some(source) = v.get("source") {
        insert_source(app, &mut tx, id, source).await?;
    }
    remember(&mut tx, "service", key, &payload, id).await?;
    db::emit(&mut tx, "service.updated", id, 1).await?;
    tx.commit().await?;
    detail(app, id).await
}
pub async fn update(app: &App, id: Uuid, v: &Value, delete: bool) -> Result<Value> {
    if delete {
        fields(v, &["expected_version"])?;
    } else {
        fields(
            v,
            &[
                "expected_version",
                "name",
                "description",
                "context",
                "enabled",
                "software_product",
                "software_version",
            ],
        )?;
    }
    let expected = v["expected_version"].as_i64().ok_or_else(invalid)?;
    let mut tx = app.pool.begin().await?;
    lock(&mut tx).await?;
    let row=sqlx::query("SELECT s.*,r.context FROM services s JOIN service_revisions r ON r.service_id=s.id AND r.version=s.version WHERE s.id=$1 FOR UPDATE OF s").bind(id).fetch_one(&mut *tx).await?;
    let version: i32 = row.get("version");
    if i64::from(version) != expected
        || row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("deleted_at")
            .is_some()
    {
        return Err(conflict());
    }
    let name = if v.get("name").is_some() {
        text(v, "name", 128, 512)?
    } else {
        row.get("name")
    };
    if name.is_empty() {
        return Err(invalid());
    }
    let description = if v.get("description").is_some() {
        text(v, "description", 2000, 4096)?
    } else {
        row.get("description")
    };
    let context = if v.get("context").is_some() {
        text(v, "context", 4000, 8192)?
    } else {
        row.get("context")
    };
    let enabled = if delete {
        false
    } else {
        boolean(v, "enabled", row.get("enabled"))?
    };
    let software = if v.get("software_product").is_some() || v.get("software_version").is_some() {
        crate::cve::declared_software(v)?
    } else {
        match (
            row.get::<Option<String>, _>("software_product"),
            row.get::<Option<String>, _>("software_version"),
        ) {
            (Some(p), Some(ver)) => Some((p, ver)),
            _ => None,
        }
    };
    let software_origin: Option<String> =
        if v.get("software_product").is_some() || v.get("software_version").is_some() {
            software.as_ref().map(|_| "operator".to_owned())
        } else {
            row.get("software_origin")
        };
    sqlx::query("UPDATE services SET name=$2,description=$3,enabled=$4,version=version+1,updated_at=now(),deleted_at=CASE WHEN $5 THEN now() ELSE NULL END,software_product=$6,software_version=$7,software_origin=$8 WHERE id=$1").bind(id).bind(&name).bind(&description).bind(enabled).bind(delete).bind(software.as_ref().map(|(p, _)| p.clone())).bind(software.as_ref().map(|(_, ver)| ver.clone())).bind(&software_origin).execute(&mut *tx).await?;
    revision(&mut tx, id, version + 1, &name, &description, &context).await?;
    if delete {
        sqlx::query("UPDATE sources SET enabled=false,deleted_at=now(),version=version+1 WHERE service_id=$1 AND deleted_at IS NULL").bind(id).execute(&mut *tx).await?;
    }
    if delete || !enabled {
        sqlx::query("UPDATE analysis_jobs j SET state=CASE WHEN $2 THEN 'superseded' ELSE 'blocked_config' END,reason=CASE WHEN $2 THEN 'service_deleted' ELSE 'service_inactive' END WHERE j.state IN('pending','preparing','blocked_config','skipped_budget') AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id) AND (EXISTS(SELECT 1 FROM incident_services i WHERE i.incident_id=j.incident_id AND i.service_id=$1) OR EXISTS(SELECT 1 FROM review_segments rs JOIN text_records tr ON tr.id=rs.record_id WHERE rs.job_id=j.id AND tr.service_id=$1))").bind(id).bind(delete).execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE analysis_jobs j SET state='pending',reason='service_reactivated',eligible_at=now() WHERE j.state='blocked_config' AND j.reason='service_inactive' AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id) AND (EXISTS(SELECT 1 FROM incident_services i WHERE i.incident_id=j.incident_id AND i.service_id=$1) OR EXISTS(SELECT 1 FROM review_segments rs JOIN text_records tr ON tr.id=rs.record_id WHERE rs.job_id=j.id AND tr.service_id=$1)) AND NOT EXISTS(SELECT 1 FROM job_services js JOIN services s ON s.id=js.service_id WHERE js.job_id=j.id AND (NOT s.enabled OR s.deleted_at IS NOT NULL))").bind(id).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE messages m SET state=j.state FROM analysis_jobs j WHERE j.message_id=m.id AND j.reason IN('service_inactive','service_deleted','service_reactivated') AND j.state IN('blocked_config','superseded','pending') AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id) AND (EXISTS(SELECT 1 FROM incident_services i WHERE i.incident_id=j.incident_id AND i.service_id=$1) OR EXISTS(SELECT 1 FROM review_segments rs JOIN text_records tr ON tr.id=rs.record_id WHERE rs.job_id=j.id AND tr.service_id=$1))").bind(id).execute(&mut *tx).await?;
    db::emit(
        &mut tx,
        if delete {
            "service.deleted"
        } else {
            "service.updated"
        },
        id,
        version + 1,
    )
    .await?;
    tx.commit().await?;
    detail(app, id).await
}
pub async fn create_source(app: &App, service: Uuid, v: &Value) -> Result<Value> {
    let key = uuid(v, "idempotency_key")?;
    let payload = hash(format!("{service}:{v}"));
    let mut tx = app.pool.begin().await?;
    lock(&mut tx).await?;
    if let Some(id) = replay(&mut tx, "source", key, &payload).await? {
        tx.commit().await?;
        return source_detail(app, id).await;
    }
    let live: bool =
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM services WHERE id=$1 FOR UPDATE")
            .bind(service)
            .fetch_one(&mut *tx)
            .await?;
    if !live {
        return Err(conflict());
    }
    let id = insert_source(app, &mut tx, service, v).await?;
    remember(&mut tx, "source", key, &payload, id).await?;
    tx.commit().await?;
    source_detail(app, id).await
}
pub async fn update_source(app: &App, id: Uuid, v: &Value, delete: bool) -> Result<Value> {
    if delete {
        fields(v, &["expected_version"])?;
    } else {
        fields(
            v,
            &[
                "expected_version",
                "kind",
                "config",
                "analysis",
                "enabled",
                "credential",
            ],
        )?;
    }
    let expected = v["expected_version"].as_i64().ok_or_else(invalid)?;
    let mut tx = app.pool.begin().await?;
    lock(&mut tx).await?;
    let row=sqlx::query("SELECT x.* FROM sources x JOIN services s ON s.id=x.service_id WHERE x.id=$1 AND s.deleted_at IS NULL FOR UPDATE OF x").bind(id).fetch_one(&mut *tx).await?;
    let version: i32 = row.get("version");
    if i64::from(version) != expected
        || row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("deleted_at")
            .is_some()
    {
        return Err(conflict());
    }
    let kind: String = row.get("kind");
    if v.get("kind").is_some_and(|x| x != &kind) {
        return Err(invalid());
    }
    let old_config: Value = row.get("config");
    let old_analysis: Value = row.get("analysis");
    let analysis = v.get("analysis").cloned().unwrap_or(old_analysis);
    validate_analysis(&analysis)?;
    validate_template_compatibility(&kind, &analysis)?;
    let config = v
        .get("config")
        .cloned()
        .unwrap_or_else(|| old_config.clone());
    if kind == "folder"
        && (old_config["root_alias"] != config["root_alias"]
            || old_config["data_class"].as_str().unwrap_or("synthetic")
                != config["data_class"].as_str().unwrap_or("synthetic"))
    {
        return Err(conflict());
    }
    if kind == "mcp" && old_config["mode"] != config["mode"] {
        return Err(conflict());
    }
    let enabled = if delete {
        false
    } else {
        boolean(v, "enabled", row.get("enabled"))?
    };
    if kind == "mcp" && enabled && !row.get::<bool, _>("enabled") {
        let checked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM source_checks WHERE source_id=$1 AND source_version=$2 AND result->>'readable'='true' AND checked_at>now()-interval '15 minutes')").bind(id).bind(version).fetch_one(&mut *tx).await?;
        if !checked || config != old_config || v.get("credential").is_some() {
            return Err(conflict());
        }
    }
    // Retiring a connection must remain possible after the operator removes its network allowlist.
    if !delete && (config != old_config || enabled) {
        validate_config(&kind, &config)?;
        unique_source(&mut tx, id, &kind, &config).await?;
    }
    if kind != "mcp" && v.get("credential").is_some() {
        return Err(invalid());
    }
    sqlx::query("UPDATE sources SET capture_version=CASE WHEN (config - 'poll_seconds') IS DISTINCT FROM ($2::jsonb - 'poll_seconds') THEN version+1 ELSE capture_version END,config=$2,analysis=$5,enabled=$3,version=version+1,updated_at=now(),deleted_at=CASE WHEN $4 THEN now() ELSE NULL END WHERE id=$1").bind(id).bind(&config).bind(enabled).bind(delete).bind(&analysis).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO source_revisions(source_id,version,config,analysis) VALUES($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(version + 1)
    .bind(config)
    .bind(analysis)
    .execute(&mut *tx)
    .await?;
    save_credential(app, &mut tx, id, v).await?;
    db::emit(&mut tx, "source.updated", id, version + 1).await?;
    tx.commit().await?;
    source_detail(app, id).await
}
pub async fn service_context(pool: &PgPool, id: Uuid) -> anyhow::Result<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('id',s.id,'name',r.name,'description',r.description,'context',r.context,'version',r.version,'context_hash',r.context_hash,'enabled',s.enabled,'deleted',s.deleted_at IS NOT NULL) FROM services s JOIN service_revisions r ON r.service_id=s.id AND r.version=s.version WHERE s.id=$1").bind(id).fetch_one(pool).await?)
}
pub async fn incident_contexts(pool: &PgPool, id: Uuid) -> anyhow::Result<Vec<Value>> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('id',s.id,'name',r.name,'description',r.description,'context',r.context,'version',r.version,'context_hash',r.context_hash,'enabled',s.enabled,'deleted',s.deleted_at IS NOT NULL) FROM incident_services i JOIN services s ON s.id=i.service_id JOIN service_revisions r ON r.service_id=s.id AND r.version=s.version WHERE i.incident_id=$1 ORDER BY s.id").bind(id).fetch_all(pool).await?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn analysis_is_closed_and_rules_are_typed() {
        let valid = json!({"system":"OpenSSH","protocol":"SSH","adapter":"native-text","context":"Un fallo no prueba acceso.","rules":[{"id":"R1","enabled":true,"threshold":5,"window_seconds":60}]});
        assert!(validate_analysis(&valid).is_ok());
        for bad in [
            json!({"system":"OpenSSH","protocol":"SSH","adapter":"native-text","context":"","rules":[{"id":"R1","enabled":true,"threshold":0,"window_seconds":60}]}),
            json!({"system":"OpenSSH","protocol":"SSH","adapter":"shell","context":"","rules":[]}),
            json!({"system":"OpenSSH","protocol":"SSH","adapter":"auto","context":"","rules":[{"id":"R1","enabled":true,"threshold":5,"window_seconds":60,"script":"rm -rf /"}]}),
        ] {
            assert!(validate_analysis(&bad).is_err());
        }
    }
    #[test]
    fn observability_templates_validate_closed() {
        let base = |rules: Value| json!({"system":"Nginx","protocol":"HTTP","adapter":"auto","context":"","rules":rules});
        // Plantilla HTTP válida con severidad cerrada
        assert!(validate_analysis(&base(json!([{"id":"encoded_path_traversal","enabled":true,"threshold":1,"window_seconds":300,"severity":"high"}]))).is_ok());
        // Sin severidad también es válida (se usa la de la plantilla)
        assert!(validate_analysis(&base(json!([{"id":"request_outside_declared_surface","enabled":false,"threshold":3,"window_seconds":300}]))).is_ok());
        // Negativas: severidad libre, condición en plantilla, id desconocido, 9 reglas
        assert!(validate_analysis(&base(json!([{"id":"encoded_path_traversal","enabled":true,"threshold":1,"window_seconds":300,"severity":"urgent"}]))).is_err());
        assert!(validate_analysis(&base(json!([{"id":"encoded_path_traversal","enabled":true,"threshold":1,"window_seconds":300,"condition":{"field":"level","operator":"eq","value":"error"}}]))).is_err());
        assert!(
            validate_analysis(&base(
                json!([{"id":"custom_rule","enabled":true,"threshold":1,"window_seconds":300}])
            ))
            .is_err()
        );
        let nine: Vec<Value> = [
            "R1",
            "R2",
            "R3",
            "request_outside_declared_surface",
            "encoded_path_traversal",
            "ambiguous_request_normalization",
            "unexpected_structure_change",
            "sensitive_structure_change",
            "encoded_path_traversal",
        ]
        .iter()
        .map(|id| json!({"id":id,"enabled":true,"threshold":1,"window_seconds":60}))
        .collect();
        assert!(validate_analysis(&base(json!(nine))).is_err());
        // R1–R3 no admiten el campo severity (su severidad es fija del motor)
        assert!(validate_analysis(&base(json!([{"id":"R1","enabled":true,"threshold":5,"window_seconds":60,"severity":"low"}]))).is_err());
    }
    #[test]
    fn custom_rules_validate_closed_and_signals_match() {
        let base = |rules: Value| json!({"system":"OpenSSH","protocol":"SSH","adapter":"auto","context":"","rules":rules});
        let custom = json!({"id":"custom:gritos-de-ayuda","name":"Gritos de ayuda","signal":"auth.failed","enabled":true,"threshold":3,"window_seconds":300,"severity":"high"});
        assert!(validate_analysis(&base(json!([custom]))).is_ok());
        // Negativas: slug inválido, señal libre, sin severidad, campo libre,
        // nombre vacío y el id histórico sin prefijo «custom:».
        for bad in [
            json!({"id":"custom:Mal Slug","name":"X","signal":"any","enabled":true,"threshold":3,"window_seconds":300,"severity":"low"}),
            json!({"id":"custom:ok","name":"X","signal":"select * from events","enabled":true,"threshold":3,"window_seconds":300,"severity":"low"}),
            json!({"id":"custom:ok","name":"X","signal":"any","enabled":true,"threshold":3,"window_seconds":300}),
            json!({"id":"custom:ok","name":"X","signal":"any","enabled":true,"threshold":3,"window_seconds":300,"severity":"low","script":"x"}),
            json!({"id":"custom:ok","name":"","signal":"any","enabled":true,"threshold":3,"window_seconds":300,"severity":"low"}),
            json!({"id":"custom_rule","name":"X","signal":"any","enabled":true,"threshold":3,"window_seconds":300,"severity":"low"}),
        ] {
            assert!(validate_analysis(&base(json!([bad]))).is_err());
        }
        assert!(custom_signal_matches("any", "http.request", "info"));
        assert!(custom_signal_matches(
            "level.error",
            "http.request",
            "error"
        ));
        assert!(!custom_signal_matches("level.error", "app.error", "warn"));
        assert!(custom_signal_matches("auth.failed", "auth.failed", "warn"));
        assert!(!custom_signal_matches(
            "auth.failed",
            "auth.success",
            "info"
        ));
        assert!(!custom_signal_matches("inventada", "auth.failed", "error"));
    }
    #[test]
    fn template_compatibility_by_source_kind() {
        let with = |id: &str| json!({"system":"X","protocol":"Y","adapter":"auto","context":"","rules":[{"id":id,"enabled":true,"threshold":1,"window_seconds":60}]});
        assert!(
            validate_template_compatibility("folder", &with("sensitive_structure_change")).is_ok()
        );
        assert!(
            validate_template_compatibility("mcp", &with("sensitive_structure_change")).is_err()
        );
        assert!(validate_template_compatibility("mcp", &with("encoded_path_traversal")).is_ok());
        assert!(
            validate_template_compatibility("folder", &with("ambiguous_request_normalization"))
                .is_ok()
        );
        assert!(template_compatibility("mcp", "unexpected_structure_change").is_some());
        assert!(template_compatibility("folder", "unexpected_structure_change").is_none());
    }
    #[test]
    fn sample_diagnostic_does_not_invent_fields() {
        assert_eq!(inspect_sample("request denied")["fields"], json!([]));
        assert_eq!(
            inspect_sample("{\"status\":403,\"path\":\"/.env\"}\n")["fields"],
            json!(["path", "status"])
        );
    }
    #[test]
    fn closed_condition_matches_only_declared_fields() {
        let c = json!({"field":"level","operator":"eq","value":"error"});
        assert!(condition_matches(&c, "error", "app"));
        assert!(!condition_matches(&c, "info", "app"));
        assert!(!condition_matches(
            &json!({"field":"host","operator":"eq","value":"x"}),
            "error",
            "app"
        ));
    }
    #[test]
    fn external_folder_requires_explicit_real_class() {
        assert!(validate_config("folder",&json!({"root_alias":"external","directory":"nginx","selector":"*.log","data_class":"real","year":2026})).is_ok());
        assert!(
            validate_config(
                "folder",
                &json!({"root_alias":"external","directory":"nginx","selector":"*.log"})
            )
            .is_err()
        );
        assert!(validate_config("folder",&json!({"root_alias":"external","directory":"../secret","selector":"*.log","data_class":"real"})).is_err());
        assert!(
            validate_config(
                "folder",
                &json!({"root_alias":"demo-logs","selector":"*.log","data_class":"real"})
            )
            .is_err()
        );
    }
    #[test]
    fn folder_selectors_are_confined() {
        for selector in [
            "../auth.log",
            "/auth.log",
            "a/b.log",
            "*auth*.log",
            "foo.txt",
            "*.log/../x.log",
        ] {
            assert!(
                validate_config(
                    "folder",
                    &json!({"root_alias":"demo-logs","selector":selector})
                )
                .is_err()
            );
        }
        assert!(
            validate_config(
                "folder",
                &json!({"root_alias":"demo-logs","selector":"nginx.log"})
            )
            .is_ok()
        );
        assert!(selectors_overlap("*.log", "nginx.log"));
        assert!(!selectors_overlap("*.log", "auth.ndjson"));
        assert!(selectors_overlap("nginx-*.log", "nginx-prod.log"));
        assert!(selectors_overlap("nginx-*.log", "nginx-*error.log"));
        assert!(!selectors_overlap("nginx-*.log", "apache-*.log"));
    }
    #[test]
    fn cursor_is_bound_to_filters() {
        let mut q = HashMap::from([("q".into(), "nginx".into())]);
        let id = json!(Uuid::new_v4());
        q.insert("cursor".into(), encode(&q, "services", "nginx", &id));
        assert!(cursor(&q, "services").is_ok());
        q.insert("q".into(), "apache".into());
        assert!(cursor(&q, "services").is_err());
    }
    #[test]
    fn mcp_does_not_accept_commands_or_arbitrary_hosts() {
        for endpoint in [
            "stdio:node",
            "http://localhost:8090/mcp",
            "http://169.254.169.254/mcp",
            "https://example.test/mcp?token=x",
        ] {
            assert!(
                validate_config(
                    "mcp",
                    &json!({"endpoint":endpoint,"resource_uri":"logs://synthetic","synthetic":true})
                )
                .is_err()
            );
        }
        assert_eq!(validate_config("mcp",&json!({"endpoint":"http://mcp-fixture:8090/mcp","resource_uri":"logs://synthetic","synthetic":true})).is_ok(),std::env::var("MCP_ALLOW_SYNTHETIC_FIXTURE").as_deref()==Ok("1"));
    }
}

#[cfg(test)]
mod directory_config_tests {
    use super::*;
    #[test]
    fn directory_is_optional_but_not_a_host_path() {
        for directory in [None, Some(""), Some("nginx"), Some("apache-httpd")] {
            let mut config = json!({"root_alias":"demo-logs","selector":"*.log"});
            if let Some(d) = directory {
                config["directory"] = json!(d);
            }
            assert!(validate_config("folder", &config).is_ok());
        }
        for directory in [
            "../nginx",
            "/etc",
            "nginx/logs",
            ".",
            "..",
            "nginx\\logs",
            "nginx logs",
        ] {
            assert!(
                validate_config(
                    "folder",
                    &json!({"root_alias":"demo-logs","directory":directory,"selector":"*.log"})
                )
                .is_err()
            );
        }
    }
}
