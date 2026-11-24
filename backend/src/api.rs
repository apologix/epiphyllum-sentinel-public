use crate::*;
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::HashMap, convert::Infallible, time::Duration};
use uuid::Uuid;
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0,axum::Json(json!({"error":{"code":self.1,"message":message(self.1),"request_id":Uuid::new_v4()}}))).into_response()
    }
}
fn message(code: &str) -> &str {
    match code {
        "source_unavailable" => {
            "No se pudo leer la fuente autorizada. Verificá el montaje, la conexión y sus permisos."
        }
        "mcp_lab_destination_denied" => {
            "El endpoint debe ser HTTPS en el puerto 443 y pertenecer a la red aislada del laboratorio (/mcp)."
        }
        "mcp_lab_ca_invalid" => "Falta un certificado CA válido para este laboratorio.",
        "mcp_lab_probe_failed" => {
            "No se pudo listar los recursos del MCP. Revisá que el laboratorio esté encendido, la credencial y el certificado."
        }
        "model_spec_missing" => {
            "El modelo elegido no tiene una ficha válida. Completá formato, límites, tarifa, fuente y fecha antes de habilitarlo."
        }
        "workspace_id_invalid" => {
            "El identificador de workspace de Claude no es válido para la ruta compatible."
        }
        "review_live_required" => "Configure una API real en Ajustes para iniciar la revisión.",
        "review_authorization_required" => {
            "Autorice primero este lote en Ajustes, con presupuesto y límite de solicitudes."
        }
        "review_in_progress" => "Ya hay una revisión en curso para este lote.",
        "review_stopped" => {
            "La revisión se detuvo para los trabajos que todavía no se enviaron. Los que ya estaban en vuelo terminan y se contabilizan una sola vez."
        }
        "review_nothing_eligible" => {
            "No hay registros elegibles para una nueva revisión; los envíos ambiguos requieren revisión manual."
        }
        "generation_paused" => "La generación está pausada. No se envió la pregunta a la API.",
        "spend_limit_in_flight" => {
            "Esperá a que terminen las solicitudes reservadas antes de activar el límite."
        }
        "unauthorized" => "Inicie una sesión administrativa local.",
        "forbidden" => "Origen o token CSRF no permitido.",
        "conflict" => "La versión cambió o la clave de idempotencia tiene otro contenido.",
        "rate_limit" => "Espere antes de volver a intentar.",
        "dependency_unavailable" => "Dependencia no disponible. El incidente permanece guardado.",
        "not_found" => "Recurso no encontrado.",
        _ => "Solicitud no válida. Revise los campos y límites.",
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::warn!(code = "api_operation_failed");
        let s = e.to_string();
        if s.contains("conflict") || s.contains("build_in_progress") {
            Self(StatusCode::CONFLICT, "conflict")
        } else {
            Self(StatusCode::BAD_REQUEST, "invalid_request")
        }
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => Self(StatusCode::NOT_FOUND, "not_found"),
            sqlx::Error::Database(ref d) if d.is_unique_violation() => {
                Self(StatusCode::CONFLICT, "conflict")
            }
            _ => {
                tracing::error!(code = "api_database_unavailable");
                Self(StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable")
            }
        }
    }
}
type Result<T> = std::result::Result<T, ApiError>;
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
}
fn uid(s: &str) -> Result<Uuid> {
    s.parse().map_err(|_| invalid())
}
fn strval<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a str> {
    let s = v[key].as_str().ok_or_else(invalid)?;
    if s.is_empty() || s.chars().count() > max {
        return Err(invalid());
    }
    Ok(s)
}
fn fields(v: &Value, allowed: &[&str]) -> Result<()> {
    let obj = v.as_object().ok_or_else(invalid)?;
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid());
    }
    Ok(())
}
fn out(v: Value) -> Response {
    axum::Json(v).into_response()
}
pub fn router(app: App) -> Router {
    Router::new().fallback(handle).with_state(app)
}
fn credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    let value = cookie
        .split(';')
        .find_map(|c| c.trim().strip_prefix("sentinel="))?;
    let (a, b) = value.split_once('.')?;
    Some((a.to_string(), b.to_string()))
}
async fn auth(app: &App, headers: &HeaderMap, write: bool) -> Result<String> {
    let (token, csrf) =
        credentials(headers).ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT csrf_hash FROM admin_sessions WHERE token_hash=$1 AND expires_at>now()",
    )
    .bind(hash(&token))
    .fetch_optional(&app.pool)
    .await?;
    if stored.as_deref() != Some(hash(&csrf).as_str()) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if write && headers.get("x-csrf-token").and_then(|s| s.to_str().ok()) != Some(csrf.as_str()) {
        return Err(ApiError(StatusCode::FORBIDDEN, "forbidden"));
    }
    Ok(csrf)
}
async fn mutation_rate(app: &App, kind: &str, limit: i64) -> Result<()> {
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(6161)")
        .execute(&mut *tx)
        .await?;
    let n:i64=sqlx::query_scalar("SELECT count(*) FROM admin_requests WHERE kind=$1 AND created_at>now()-interval '60 seconds'").bind(kind).fetch_one(&mut *tx).await?;
    if n >= limit {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limit"));
    }
    sqlx::query("INSERT INTO admin_requests(kind) VALUES($1)")
        .bind(kind)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
async fn handle(State(app): State<App>, req: Request) -> Result<Response> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let headers = req.headers().clone();
    if path == "/metrics" && method == Method::GET {
        let counts:Value=sqlx::query_scalar("SELECT jsonb_build_object('records',(SELECT count(*) FROM text_records),'review_segments',(SELECT count(*) FROM review_segments),'review_completed_segments',(SELECT count(*) FROM review_segments WHERE disposition IS NOT NULL),'events',(SELECT count(*) FROM events),'ingestion_errors',(SELECT count(*) FROM ingestion_errors),'detection_pending',(SELECT count(*) FROM detection_work WHERE state='pending'),'incidents',(SELECT count(*) FROM incidents),'generation_pending',(SELECT count(*) FROM analysis_jobs WHERE state IN('pending','preparing','reserved','in_flight'))) || coalesce((SELECT jsonb_object_agg('coverage_'||coverage_state,n) FROM (SELECT coverage_state,count(*) AS n FROM record_coverage GROUP BY coverage_state) states),'{}')").fetch_one(&app.pool).await?;
        let text = counts
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| format!("# TYPE sentinel_{key} gauge\nsentinel_{key} {value}\n"))
            .collect::<String>();
        return Ok(([("content-type", "text/plain; version=0.0.4")], text).into_response());
    }
    if path == "/api/v1/health/live" {
        return Ok(out(json!({"status":"alive"})));
    }
    if path == "/api/v1/health/ready" {
        let db = sqlx::query("SELECT 1").execute(&app.pool).await.is_ok();
        let source = std::fs::metadata(&app.config.log_root).is_ok();
        let leadership = app.leadership.load(std::sync::atomic::Ordering::SeqCst);
        let response = out(
            json!({"ready":db&&source&&leadership,"checks":{"database":db,"source":source,"leadership":leadership}}),
        );
        return Ok(if db && source && leadership {
            response
        } else {
            (StatusCode::SERVICE_UNAVAILABLE, response).into_response()
        });
    }
    let expected = reqwest::Url::parse(&app.config.origin).map_err(|_| invalid())?;
    let expected_host = format!(
        "{}{}",
        expected.host_str().unwrap_or("localhost"),
        expected.port().map(|p| format!(":{p}")).unwrap_or_default()
    );
    if headers.get("host").and_then(|s| s.to_str().ok()) != Some(expected_host.as_str()) {
        return Err(ApiError(StatusCode::FORBIDDEN, "forbidden"));
    }
    let write = method != Method::GET;
    if (write || headers.contains_key("origin"))
        && headers.get("origin").and_then(|s| s.to_str().ok()) != Some(app.config.origin.as_str())
    {
        return Err(ApiError(StatusCode::FORBIDDEN, "forbidden"));
    }
    let query: HashMap<String, String> = req
        .uri()
        .query()
        .map(|q| {
            reqwest::Url::parse(&format!("http://unused/?{q}"))
                .unwrap()
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    let max = if path.ends_with("/messages") {
        8192
    } else if path == "/api/v1/session" {
        4096
    } else {
        65536
    };
    let body = if write {
        if method != Method::DELETE
            && headers
                .get("content-type")
                .and_then(|s| s.to_str().ok())
                .is_none_or(|s| !s.starts_with("application/json"))
        {
            return Err(ApiError(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "json_required",
            ));
        }
        let b = to_bytes(req.into_body(), max)
            .await
            .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"))?;
        if b.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&b).map_err(|_| invalid())?
        }
    } else {
        json!({})
    };
    if path == "/api/v1/session" && method == Method::POST {
        mutation_rate(&app, "login", 5).await?;
        fields(&body, &["secret"])?;
        let secret = strval(&body, "secret", 512)?;
        if !constant_time_eq(
            hash(secret).as_bytes(),
            hash(&app.config.admin_secret).as_bytes(),
        ) {
            return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
        }
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let csrf = Uuid::new_v4().simple().to_string();
        sqlx::query("INSERT INTO admin_sessions VALUES($1,$2,now()+interval '8 hours')")
            .bind(hash(&token))
            .bind(hash(&csrf))
            .execute(&app.pool)
            .await?;
        let mut response = out(json!({"authenticated":true,"csrf_token":csrf}));
        let cookie = format!(
            "sentinel={token}.{csrf}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{}",
            if app.config.origin.starts_with("https:") {
                "; Secure"
            } else {
                ""
            }
        );
        response
            .headers_mut()
            .insert("set-cookie", cookie.parse().unwrap());
        return Ok(response);
    }
    let csrf = auth(&app, &headers, write).await?;
    if path == "/api/v1/session" {
        if method == Method::DELETE {
            *app.authorization.lock().await = None;
            let (token, _) = credentials(&headers).unwrap();
            sqlx::query("DELETE FROM admin_sessions WHERE token_hash=$1")
                .bind(hash(token))
                .execute(&app.pool)
                .await?;
            let mut r = out(json!({"authenticated":false}));
            r.headers_mut().insert(
                "set-cookie",
                "sentinel=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                    .parse()
                    .unwrap(),
            );
            return Ok(r);
        }
        if method == Method::GET {
            return Ok(out(json!({"authenticated":true,"csrf_token":csrf})));
        }
    }
    if write {
        mutation_rate(&app, "mutation", 30).await?;
    }
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 3 || parts[..2] != ["api", "v1"] {
        return Err(ApiError(StatusCode::NOT_FOUND, "not_found"));
    }
    let rest = &parts[2..];
    match (method.as_str(), rest) {
        ("POST", ["sources", id, "check"]) => {
            fields(&body, &[])?;
            let source_id = uid(id)?;
            let row = sqlx::query(
                "SELECT kind,config,version FROM sources WHERE id=$1 AND deleted_at IS NULL",
            )
            .bind(source_id)
            .fetch_one(&app.pool)
            .await?;
            let cfg: Value = row.get("config");
            if row.get::<String, _>("kind") == "mcp" {
                let credential: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
                    "SELECT ciphertext,nonce FROM source_credentials WHERE source_id=$1",
                )
                .bind(source_id)
                .fetch_optional(&app.pool)
                .await?;
                let credential = credential
                    .map(|(cipher, nonce)| -> Result<String> {
                        let master = app.config.master_key.as_deref().ok_or_else(invalid)?;
                        decrypt(master, &cipher, &nonce).map_err(|_| invalid())
                    })
                    .transpose()?;
                let endpoint = cfg["endpoint"].as_str().ok_or_else(invalid)?;
                let uri = cfg["resource_uri"].as_str().ok_or_else(invalid)?;
                let sample = if cfg["mode"] == "incremental_lab" {
                    mcp::check_lab_resource(
                        endpoint,
                        uri,
                        credential.as_deref().ok_or_else(invalid)?,
                        cfg.get("ca_pem").and_then(|v| v.as_str()),
                    )
                    .await
                } else {
                    mcp::read_resource(endpoint, uri, credential.as_deref()).await
                };
                let result = match sample {
                    Ok(sample) => {
                        let metadata = if cfg["mode"] == "incremental_lab" {
                            serde_json::from_str::<Value>(&sample)
                                .ok()
                                .map(|page| page["service"].clone())
                        } else {
                            None
                        };
                        json!({"readable":true,"connection_attempted":true,"resource_uri":uri,"bytes":sample.len(),"service":metadata,"sample":contracts::redact(&sample.chars().take(4096).collect::<String>(),&app.config.session_id),"interpretation":services::inspect_sample(&sample),"continuity":if cfg["mode"] == "incremental_lab" {"incremental_lab"} else {"immutable_snapshot"},"limited":sample.len()>4096})
                    }
                    Err(_) => {
                        json!({"readable":false,"connection_attempted":true,"resource_uri":uri,"diagnostic":"mcp_read_failed"})
                    }
                };
                sqlx::query("INSERT INTO source_checks(source_id,source_version,result) VALUES($1,$2,$3) ON CONFLICT(source_id) DO UPDATE SET source_version=$2,checked_at=now(),result=$3").bind(source_id).bind(row.get::<i32,_>("version")).bind(&result).execute(&app.pool).await?;
                return Ok(out(result));
            }
            let root = match cfg["root_alias"].as_str() {
                Some("demo-logs") => std::path::Path::new(&app.config.log_root),
                Some("external") => std::path::Path::new("/data/external"),
                _ => return Err(invalid()),
            };
            let directory = cfg["directory"].as_str().unwrap_or("");
            let handle = collector::safe_directory(root, directory)
                .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "source_unavailable"))?;
            if cfg["root_alias"] == "external" {
                collector::require_read_only(&handle)
                    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "source_unavailable"))?;
            }
            use std::os::fd::AsRawFd;
            let mut matching = 0usize;
            let mut limited = false;
            let mut sample = String::new();
            for entry in std::fs::read_dir(format!("/proc/self/fd/{}", handle.as_raw_fd()))
                .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "source_unavailable"))?
            {
                let entry = entry
                    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "source_unavailable"))?;
                if collector::selector_matches(
                    cfg["selector"].as_str().unwrap_or(""),
                    &entry.file_name().to_string_lossy(),
                ) && collector::safe_open(&root.join(directory).join(entry.file_name()), root)
                    .is_ok_and(|file| {
                        cfg["root_alias"] != "external"
                            || collector::require_read_only(&file).is_ok()
                    })
                {
                    matching += 1;
                    if sample.is_empty() {
                        use std::io::Read;
                        if let Ok(mut file) = collector::safe_open(
                            &root.join(directory).join(entry.file_name()),
                            root,
                        ) {
                            let mut bytes = vec![0; 4096];
                            if let Ok(n) = file.read(&mut bytes) {
                                sample = String::from_utf8_lossy(&bytes[..n]).to_string();
                            }
                        }
                    }
                    if matching >= 1000 {
                        limited = true;
                        break;
                    }
                }
            }
            let result = json!({"readable":true,"connection_attempted":false,"matching_files":matching,"limited":limited,"sample":contracts::redact(&sample,&app.config.session_id),"interpretation":services::inspect_sample(&sample),"root_alias":cfg["root_alias"],"directory":directory});
            sqlx::query("INSERT INTO source_checks(source_id,source_version,result) VALUES($1,$2,$3) ON CONFLICT(source_id) DO UPDATE SET source_version=$2,checked_at=now(),result=$3").bind(source_id).bind(row.get::<i32,_>("version")).bind(&result).execute(&app.pool).await?;
            return Ok(out(result));
        }
        ("POST", ["sources", id, "rules", "preview"]) => {
            fields(&body, &[])?;
            return Ok(out(services::preview_rules(&app, uid(id)?).await?));
        }
        ("GET", ["sources", id, "revisions"]) => {
            return Ok(out(services::source_history(&app, uid(id)?, &query).await?));
        }
        ("POST", ["sources", id, "restore"]) => {
            return Ok(out(services::restore_source_analysis(
                &app,
                uid(id)?,
                &body,
            )
            .await?));
        }
        ("GET", ["lab-analyses", "profiles"]) => {
            if !query.is_empty() {
                return Err(invalid());
            }
            return Ok(out(lab_analysis::profiles()));
        }
        ("GET", ["lab-analyses"]) => {
            return Ok(out(lab_analysis::list(&app, &query).await?));
        }
        ("POST", ["lab-analyses"]) => {
            return Ok((
                StatusCode::CREATED,
                out(lab_analysis::create(&app, &body).await?),
            )
                .into_response());
        }
        ("GET", ["lab-analyses", id]) => {
            if !query.is_empty() {
                return Err(invalid());
            }
            return Ok(out(lab_analysis::detail(&app, uid(id)?).await?));
        }
        ("GET", ["services"]) => return Ok(out(services::list(&app, &query).await?)),
        ("POST", ["services"]) => {
            return Ok((
                StatusCode::CREATED,
                out(services::create(&app, &body).await?),
            )
                .into_response());
        }
        ("GET", ["services", id]) => {
            if !query.is_empty() {
                return Err(invalid());
            }
            return Ok(out(services::detail(&app, uid(id)?).await?));
        }
        ("PUT", ["services", id]) => {
            return Ok(out(services::update(&app, uid(id)?, &body, false).await?));
        }
        ("DELETE", ["services", id]) => {
            return Ok(out(services::update(&app, uid(id)?, &body, true).await?));
        }
        ("GET", ["services", id, "sources"]) => {
            return Ok(out(services::source_list(&app, uid(id)?, &query).await?));
        }
        ("GET", ["services", id, "cve"]) => {
            return Ok(out(crate::cve::latest(&app, uid(id)?).await?));
        }
        ("GET", ["services", id, "structure"]) => {
            return Ok(out(crate::structure::overview(&app, uid(id)?).await?));
        }
        ("GET", ["services", id, "observability"]) => {
            return Ok(out(crate::observability::list_entries(
                &app,
                uid(id)?,
                &query,
            )
            .await?));
        }
        ("POST", ["services", id, "observability"]) => {
            fields(&body, &["scope", "entry_kind", "config", "description"])?;
            return Ok((
                StatusCode::CREATED,
                out(crate::observability::create_entry(&app, uid(id)?, &body).await?),
            )
                .into_response());
        }
        ("PUT", ["services", id, "observability", entry]) => {
            fields(&body, &["config", "description", "status"])?;
            return Ok(out(crate::observability::update_entry(
                &app,
                uid(id)?,
                uid(entry)?,
                &body,
            )
            .await?));
        }
        ("GET", ["services", id, "observability", entry, "history"]) => {
            return Ok(out(crate::observability::entry_history(
                &app,
                uid(id)?,
                uid(entry)?,
            )
            .await?));
        }
        ("POST", ["services", id, "observability", entry, "revert"]) => {
            fields(&body, &["revision"])?;
            return Ok(out(crate::observability::revert_entry(
                &app,
                uid(id)?,
                uid(entry)?,
                &body,
            )
            .await?));
        }
        ("POST", ["services", id, "observability-seed-lab"]) => {
            return Ok((
                StatusCode::CREATED,
                out(crate::observability::seed_lab(&app, uid(id)?).await?),
            )
                .into_response());
        }
        ("POST", ["services", id, "structure", "captures"]) => {
            fields(&body, &["root_alias", "directory"])?;
            return Ok((
                StatusCode::CREATED,
                out(crate::structure::capture(&app, uid(id)?, &body).await?),
            )
                .into_response());
        }
        ("GET", ["services", id, "cve", "banner-suggestions"]) => {
            return Ok(out(crate::cve::banner_suggestions(&app, uid(id)?).await?));
        }
        ("GET", ["cve", "services"]) => {
            return Ok(out(crate::cve::services_summary(&app).await?));
        }
        ("GET", ["cve", "findings"]) => {
            return Ok(out(crate::cve::findings_page(&app, &query).await?));
        }
        ("POST", ["cve", "checks", "run-all"]) => {
            fields(&body, &[])?;
            return Ok(out(crate::cve::run_all(&app).await?));
        }
        ("GET", ["cve-findings", id, "explanations"]) => {
            return Ok(out(crate::cve::list_explanations(&app, uid(id)?).await?));
        }
        ("POST", ["cve-findings", id, "explanations"]) => {
            fields(&body, &["question"])?;
            return Ok((
                StatusCode::CREATED,
                out(crate::cve::create_explanation(&app, uid(id)?, &body).await?),
            )
                .into_response());
        }
        ("POST", ["services", id, "cve-checks"]) => {
            fields(&body, &[])?;
            return Ok((
                StatusCode::CREATED,
                out(crate::cve::run_check(&app, uid(id)?).await?),
            )
                .into_response());
        }
        ("POST", ["services", id, "sources"]) => {
            return Ok((
                StatusCode::CREATED,
                out(services::create_source(&app, uid(id)?, &body).await?),
            )
                .into_response());
        }
        ("GET", ["sources", id]) => {
            if !query.is_empty() {
                return Err(invalid());
            }
            return Ok(out(services::source_detail(&app, uid(id)?).await?));
        }
        ("PUT", ["sources", id]) => {
            return Ok(out(
                services::update_source(&app, uid(id)?, &body, false).await?
            ));
        }
        ("DELETE", ["sources", id]) => {
            return Ok(out(
                services::update_source(&app, uid(id)?, &body, true).await?
            ));
        }
        _ => (),
    }
    if method == Method::GET {
        match rest {
            ["notifications"] => {
                if !query.is_empty() {
                    return Err(invalid());
                }
                let items: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(n)||jsonb_build_object('title',i.title,'severity',i.severity,'rule_id',i.rule_id,'service',coalesce((SELECT string_agg(s.name,', ' ORDER BY s.name) FROM incident_services ss JOIN services s ON s.id=ss.service_id WHERE ss.incident_id=i.id),i.group_key->>'service'),'services',(SELECT coalesce(jsonb_agg(jsonb_build_object('id',s.id,'name',s.name,'enabled',s.enabled,'deleted_at',s.deleted_at)),'[]') FROM incident_services ss JOIN services s ON s.id=ss.service_id WHERE ss.incident_id=i.id),'opened_at',i.opened_at,'followup_state',i.followup_state,'evidence_count',(SELECT count(*) FROM incident_events e WHERE e.incident_id=i.id),'analysis_state',(SELECT j.state FROM analysis_jobs j WHERE j.incident_id=i.id AND j.kind='analysis' ORDER BY j.created_at DESC LIMIT 1),'summary',(SELECT a.response->>'summary' FROM analyses a JOIN analysis_jobs j ON j.id=a.job_id WHERE j.incident_id=i.id AND j.kind='analysis' AND a.origin='live' ORDER BY a.created_at DESC LIMIT 1),'recommendations',(SELECT a.response->'recommendations' FROM analyses a JOIN analysis_jobs j ON j.id=a.job_id WHERE j.incident_id=i.id AND j.kind='analysis' AND a.origin='live' ORDER BY a.created_at DESC LIMIT 1)) FROM notifications n JOIN incidents i ON i.id=n.incident_id ORDER BY n.created_at DESC LIMIT 100").fetch_all(&app.pool).await?;
                let unread: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM notifications WHERE read_at IS NULL")
                        .fetch_one(&app.pool)
                        .await?;
                return Ok(out(json!({"items":items,"unread_count":unread})));
            }
            ["dashboard"] => {
                if !query.is_empty() {
                    return Err(invalid());
                }
                return Ok(out(crate::dashboard::summary(&app).await?));
            }
            ["reports"] => return Ok(out(reports(&app, &query).await?)),
            ["reports", id] => return Ok(out(report(&app, uid(id)?).await?)),
            ["reports", id, "evidence"] => {
                return Ok(out(events(&app, &query, Some(uid(id)?)).await?));
            }
            ["review-batches"] => {
                let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',run_id,'received_at',min(received_at),'records',count(*)) FROM text_records GROUP BY run_id ORDER BY min(received_at) DESC LIMIT 100").fetch_all(&app.pool).await?;
                return Ok(out(json!({"items":rows})));
            }
            ["coverage"] => {
                if query.keys().any(|k| {
                    !["run_id", "service", "service_id", "from", "to"].contains(&k.as_str())
                }) {
                    return Err(invalid());
                }
                return Ok(out(review::coverage(
                    &app,
                    query.get("run_id").map(|s| uid(s)).transpose()?,
                    query.get("service").map(String::as_str),
                    query.get("service_id").map(|s| uid(s)).transpose()?,
                    date(&query, "from")?,
                    date(&query, "to")?,
                )
                .await?));
            }
            ["records"] => {
                let (limit, cursor) = page(
                    &query,
                    &path,
                    &[
                        "limit",
                        "cursor",
                        "run_id",
                        "service",
                        "service_id",
                        "state",
                        "from",
                        "to",
                    ],
                )?;
                if query.get("state").is_some_and(|s| {
                    ![
                        "mock",
                        "mixed",
                        "live",
                        "local",
                        "pending",
                        "in_progress",
                        "inconclusive",
                        "failed",
                        "unknown",
                        "blocked",
                        "unavailable",
                    ]
                    .contains(&s.as_str())
                }) {
                    return Err(invalid());
                }
                let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(r)-'original'||jsonb_build_object('safe_text',CASE WHEN r.data_class='real' THEN (SELECT string_agg(seg.content,'' ORDER BY seg.ordinal) FROM review_segments seg WHERE seg.record_id=r.id AND seg.revision=(SELECT max(z.revision) FROM review_segments z WHERE z.record_id=r.id)) ELSE r.safe_text END,'service',coalesce((SELECT name FROM services WHERE id=r.service_id),r.service),'locations',(SELECT jsonb_agg(to_jsonb(l)) FROM record_locations l WHERE l.record_id=r.id),'mcp_locations',(SELECT jsonb_agg(to_jsonb(m)) FROM mcp_record_locations m WHERE m.record_id=r.id),'jobs',(SELECT jsonb_agg(DISTINCT jsonb_build_object('id',j.id,'state',j.state,'reason',j.reason,'model',j.model,'provider',j.provider)) FROM review_segments s JOIN analysis_jobs j ON j.id=s.job_id WHERE s.record_id=r.id)) FROM record_coverage r WHERE ($1::bigint IS NULL OR record_seq<$1) AND ($2::uuid IS NULL OR run_id=$2) AND ($3::text IS NULL OR service=$3) AND ($4::text IS NULL OR coverage_state=$4) AND ($5::timestamptz IS NULL OR received_at>=$5) AND ($6::timestamptz IS NULL OR received_at<=$6) AND ($8::uuid IS NULL OR r.service_id=$8) ORDER BY record_seq DESC LIMIT $7").bind(cursor).bind(query.get("run_id").map(|s|uid(s)).transpose()?).bind(query.get("service")).bind(query.get("state")).bind(date(&query,"from")?).bind(date(&query,"to")?).bind(limit+1).bind(query.get("service_id").map(|s|uid(s)).transpose()?).fetch_all(&app.pool).await?;
                return Ok(out(paginate(rows, limit, "record_seq", &path, &query)));
            }
            ["records", id] => {
                if !query.is_empty() {
                    return Err(invalid());
                }
                let r: Value=sqlx::query_scalar("SELECT to_jsonb(r)-'original'||jsonb_build_object('safe_text',CASE WHEN r.data_class='real' THEN (SELECT string_agg(seg.content,'' ORDER BY seg.ordinal) FROM review_segments seg WHERE seg.record_id=r.id AND seg.revision=(SELECT max(z.revision) FROM review_segments z WHERE z.record_id=r.id)) ELSE r.safe_text END,'service',coalesce((SELECT name FROM services WHERE id=r.service_id),r.service),'segments',(SELECT jsonb_agg(to_jsonb(s) ORDER BY ordinal) FROM review_segments s WHERE s.record_id=r.id)) FROM record_coverage r WHERE id=$1").bind(uid(id)?).fetch_one(&app.pool).await?;
                return Ok(out(r));
            }
            ["business-rules"] => {
                return Ok(out(sqlx::query_scalar::<_, Value>(
                    "SELECT to_jsonb(b) FROM business_rule_sets b ORDER BY version DESC LIMIT 1",
                )
                .fetch_one(&app.pool)
                .await?));
            }
            ["events"] => return Ok(out(events(&app, &query, None).await?)),
            ["sources"] => {
                return Ok(out(services::all_sources(&app, &query).await?));
            }
            ["status"] => {
                let embedding = app
                    .client
                    .get(format!("{}/health", app.config.embeddings_url))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success());
                let active: Option<Value> =
                    sqlx::query_scalar("SELECT to_jsonb(k) FROM knowledge_state k")
                        .fetch_optional(&app.pool)
                        .await?;
                let settings = settings(&app).await?;
                return Ok(out(
                    json!({"supported_log_formats":["Sentinel NDJSON","SSH auth.log","nginx error.log","Apache error.log","HAProxy HTTP","Syslog RFC5424"],"version":"0.1.0","mode":settings["profile"]["mode"],"model":settings["profile"]["model"],"embeddings":if embedding{"healthy"}else{"blocked"},"knowledge":active,"generation_paused":gateway::generation_paused(),"block_reasons":if gateway::generation_paused(){json!(["generation_paused"])}else{json!([])},"authorization":settings["authorization"],"updated_at":chrono::Utc::now(),"data_class":"synthetic"}),
                ));
            }
            ["costs"] => {
                return Ok(out(
                    json!({"session_id":app.config.session_id,"accounts":db::rows(&app.pool,"SELECT to_jsonb(a)||jsonb_build_object('remaining_units',CASE WHEN a.scope='session' AND a.cap_enabled THEN greatest(0::bigint,a.limit_units-(a.spent_units-a.cap_baseline_spent_units)-a.reserved_units) ELSE NULL END) FROM budget_accounts a ORDER BY scope,scope_key").await?,"jobs":db::rows(&app.pool,"SELECT jsonb_build_object('state',state,'count',count(*)) FROM analysis_jobs GROUP BY state").await?,"unit_usd":"0.00000001","generation":"ver origen de cada intento"}),
                ));
            }
            ["stream"] => return stream(&app, &headers).await,
            ["reports", id, "conversation"] => {
                let id = uid(id)?;
                let (limit, cursor) = page(&query, &path, &["cursor", "limit"])?;
                let messages:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(m)||jsonb_build_object('job',(SELECT to_jsonb(j)||jsonb_build_object('analysis',(SELECT to_jsonb(a) FROM analyses a WHERE a.job_id=j.id AND a.origin<>'mock'),'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]') FROM analysis_attempts t WHERE t.job_id=j.id)) FROM analysis_jobs j WHERE j.message_id=m.id)) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.incident_id=$1 AND m.ordinal>$2 AND NOT (m.role='assistant' AND EXISTS(SELECT 1 FROM analysis_jobs jj JOIN analyses aa ON aa.job_id=jj.id WHERE jj.message_id=m.reply_to AND aa.origin='mock')) ORDER BY m.ordinal LIMIT $3").bind(id).bind(cursor.unwrap_or(0)).bind(limit+1).fetch_all(&app.pool).await?;
                return Ok(out(paginate(messages, limit, "ordinal", &path, &query)));
            }
            ["knowledge"] => {
                let (limit, cursor) = page(&query, &path, &["cursor", "limit", "kind", "state"])?;
                let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(d)||jsonb_build_object('revision',r.revision,'state',r.state,'text',r.text,'metadata',r.metadata) FROM knowledge_documents d JOIN LATERAL(SELECT * FROM knowledge_revisions WHERE document_id=d.id ORDER BY revision DESC LIMIT 1)r ON true WHERE ($1::text IS NULL OR d.kind=$1) AND ($2::text IS NULL OR r.state=$2) ORDER BY d.created_at,d.id LIMIT $3 OFFSET $4").bind(query.get("kind")).bind(query.get("state")).bind(limit+1).bind(cursor.unwrap_or(0)).fetch_all(&app.pool).await?;
                let mut p = paginate(rows, limit, "", &path, &query);
                if p["next_cursor"].is_string() {
                    p["next_cursor"] =
                        json!(cursor_encode(cursor.unwrap_or(0) + limit, &path, &query));
                }
                p["active"] =
                    sqlx::query_scalar::<_, Value>("SELECT to_jsonb(k) FROM knowledge_state k")
                        .fetch_optional(&app.pool)
                        .await?
                        .unwrap_or(Value::Null);
                p["builds"]=json!(db::rows(&app.pool,"SELECT to_jsonb(c)||jsonb_build_object('documents',(SELECT count(*) FROM corpus_members m WHERE m.corpus_id=c.id),'vectors',(SELECT count(*) FROM knowledge_embeddings e WHERE e.corpus_id=c.id)) FROM corpus_versions c ORDER BY created_at DESC LIMIT 100").await?);
                return Ok(out(p));
            }
            ["knowledge", id] => {
                let id = uid(id)?;
                let row:Value=sqlx::query_scalar("SELECT to_jsonb(d)||jsonb_build_object('revisions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY revision DESC) FROM knowledge_revisions r WHERE document_id=d.id)) FROM knowledge_documents d WHERE id=$1").bind(id).fetch_one(&app.pool).await?;
                return Ok(out(row));
            }
            ["knowledge", "builds", id] => {
                let row:Value=sqlx::query_scalar("SELECT to_jsonb(c)||jsonb_build_object('vectors',(SELECT count(*) FROM knowledge_embeddings WHERE corpus_id=c.id),'manifest',(SELECT jsonb_agg(to_jsonb(m)) FROM corpus_members m WHERE corpus_id=c.id)) FROM corpus_versions c WHERE id=$1").bind(uid(id)?).fetch_one(&app.pool).await?;
                return Ok(out(row));
            }
            ["settings", "ai"] => return Ok(out(settings(&app).await?)),
            ["settings", "cve"] => return Ok(out(crate::cve::settings(&app).await?)),
            _ => (),
        }
    }
    match (method.as_str(), rest) {
        ("POST", ["notifications", id, "read"]) => {
            fields(&body, &[])?;
            let id = uid(id)?;
            let mut tx = app.pool.begin().await?;
            let changed = sqlx::query(
                "UPDATE notifications SET read_at=coalesce(read_at,now()) WHERE incident_id=$1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed == 0 {
                return Err(ApiError(StatusCode::NOT_FOUND, "not_found"));
            }
            db::emit(&mut tx, "notification.updated", id, 1).await?;
            tx.commit().await?;
            Ok(out(json!({"read":true})))
        }
        ("POST", ["reports", id, "followup"]) => {
            fields(&body, &["action", "observation"])?;
            let id = uid(id)?;
            let action = strval(&body, "action", 20)?;
            if !["acknowledged", "closed", "reopened", "observation"].contains(&action) {
                return Err(invalid());
            }
            let observation = body
                .get("observation")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if observation.chars().count() > 2000
                || (action == "observation" && observation.is_empty())
            {
                return Err(invalid());
            }
            let mut tx = app.pool.begin().await?;
            let current: String =
                sqlx::query_scalar("SELECT followup_state FROM incidents WHERE id=$1 FOR UPDATE")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?;
            let next = match action {
                "acknowledged" if current == "open" => "acknowledged",
                "closed" if current == "acknowledged" => "closed",
                "reopened" if current == "closed" => "open",
                "observation" => current.as_str(),
                _ => return Err(ApiError(StatusCode::CONFLICT, "conflict")),
            };
            sqlx::query("UPDATE incidents SET followup_state=$2,report_version=report_version+1 WHERE id=$1").bind(id).bind(next).execute(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO incident_actions(incident_id,action,observation) VALUES($1,$2,$3)",
            )
            .bind(id)
            .bind(action)
            .bind(observation)
            .execute(&mut *tx)
            .await?;
            db::emit(&mut tx, "report.updated", id, 1).await?;
            tx.commit().await?;
            Ok(out(json!({"state":next})))
        }
        ("POST", ["reports", id, "chat-presence"]) => {
            fields(&body, &["visitor_id"])?;
            let incident = uid(id)?;
            let visitor = uid(strval(&body, "visitor_id", 36)?)?;
            sqlx::query("INSERT INTO chat_worker_presence(incident_id,visitor_id,expires_at) VALUES($1,$2,now()+interval '35 seconds') ON CONFLICT(incident_id,visitor_id) DO UPDATE SET expires_at=excluded.expires_at").bind(incident).bind(visitor).execute(&app.pool).await?;
            Ok(out(json!({"active":true})))
        }
        ("DELETE", ["reports", id, "chat-presence", visitor]) => {
            sqlx::query("DELETE FROM chat_worker_presence WHERE incident_id=$1 AND visitor_id=$2")
                .bind(uid(id)?)
                .bind(uid(visitor)?)
                .execute(&app.pool)
                .await?;
            Ok(out(json!({"active":false})))
        }
        ("POST", ["reviews", "stop"]) => {
            fields(&body, &["run_id"])?;
            let run = uid(strval(&body, "run_id", 36)?)?;
            return Ok(out(crate::review::stop(&app, run).await?));
        }
        ("POST", ["reviews"]) => {
            fields(&body, &["run_id", "failed_only"])?;
            let run = uid(strval(&body, "run_id", 36)?)?;
            let failed_only = match body.get("failed_only") {
                None => false,
                Some(v) => v.as_bool().ok_or_else(invalid)?,
            };
            let profile: Value =
                sqlx::query_scalar("SELECT value FROM app_settings WHERE key='ai'")
                    .fetch_one(&app.pool)
                    .await?;
            if profile["mode"] != "live" || profile["provider"] == "mock" {
                return Err(ApiError(StatusCode::CONFLICT, "review_live_required"));
            }
            let mut tx = app.pool.begin().await?;
            sqlx::query("DELETE FROM review_stops WHERE run_id=$1")
                .bind(run)
                .execute(&mut *tx)
                .await?;
            sqlx::query("SELECT pg_advisory_xact_lock(9797)")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SELECT pg_advisory_xact_lock(7616)")
                .execute(&mut *tx)
                .await?;
            let busy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM review_segments s JOIN text_records r ON r.id=s.record_id LEFT JOIN analysis_jobs j ON j.id=s.job_id WHERE r.run_id=$1 AND s.revision=(SELECT max(z.revision) FROM review_segments z WHERE z.record_id=r.id) AND (s.job_id IS NULL OR j.state IN('pending','preparing','reserved','in_flight'))) ").bind(run).fetch_one(&mut *tx).await?;
            if busy {
                return Err(ApiError(StatusCode::CONFLICT, "review_in_progress"));
            }
            let rows=sqlx::query("SELECT s.* FROM review_segments s JOIN text_records r ON r.id=s.record_id LEFT JOIN analysis_jobs j ON j.id=s.job_id WHERE r.run_id=$1 AND (NOT $2 OR j.state='failed') AND r.local_reason IS NULL AND r.content_expired_at IS NULL AND s.revision=(SELECT max(z.revision) FROM review_segments z WHERE z.record_id=r.id) AND NOT EXISTS(SELECT 1 FROM review_segments x JOIN analysis_jobs y ON y.id=x.job_id WHERE x.record_id=r.id AND y.state='unknown') AND NOT EXISTS(SELECT 1 FROM review_segments x LEFT JOIN analysis_jobs y ON y.id=x.job_id WHERE x.record_id=r.id AND x.revision=s.revision AND x.disposition IS NULL AND (y.state NOT IN('blocked_config','skipped_budget','failed') OR (y.state<>'failed' AND EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=y.id)))) AND (s.disposition IS NOT NULL OR (j.state='failed' OR (j.state IN('blocked_config','skipped_budget','stopped') AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id)))) ORDER BY r.record_seq,s.ordinal FOR UPDATE OF s").bind(run).bind(failed_only).fetch_all(&mut *tx).await?;
            if rows.is_empty() {
                return Err(ApiError(StatusCode::CONFLICT, "review_nothing_eligible"));
            }
            for row in &rows {
                let id: Uuid = row.get("record_id");
                let rev: i32 = row.get("revision");
                let ord: i32 = row.get("ordinal");
                sqlx::query("INSERT INTO review_segments(id,record_id,revision,ordinal,byte_start,byte_end,content,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(Uuid::new_v5(&id,format!("review{}:{}",rev+1,ord).as_bytes())).bind(id).bind(rev+1).bind(ord).bind(row.get::<i32,_>("byte_start")).bind(row.get::<i32,_>("byte_end")).bind(row.get::<String,_>("content")).bind(row.get::<String,_>("content_hash")).execute(&mut *tx).await?;
            }
            db::emit(&mut tx, "coverage.updated", run, 1).await?;
            tx.commit().await?;
            Ok((
                StatusCode::ACCEPTED,
                axum::Json(json!({"segments":rows.len()})),
            )
                .into_response())
        }
        ("PUT", ["business-rules"]) => {
            fields(&body, &["expected_version", "definition"])?;
            let version = body["expected_version"]
                .as_i64()
                .filter(|v| *v >= 1 && *v < i32::MAX as i64)
                .ok_or_else(invalid)? as i32;
            let mut definition = review::validate_rules(body["definition"].clone())?;
            for rule in definition["rules"].as_array_mut().ok_or_else(invalid)? {
                if let Some(name) = rule.get("service").and_then(Value::as_str) {
                    let id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM services WHERE lower(name)=lower($1) AND deleted_at IS NULL").bind(name).fetch_optional(&app.pool).await?;
                    rule["service_id"] = json!(id.ok_or_else(invalid)?);
                    rule["service"] = Value::Null;
                }
                if let Some(id) = rule.get("service_id").filter(|v| !v.is_null()) {
                    let id = uid(id.as_str().ok_or_else(invalid)?)?;
                    let valid: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM services WHERE id=$1 AND deleted_at IS NULL)",
                    )
                    .bind(id)
                    .fetch_one(&app.pool)
                    .await?;
                    if !valid {
                        return Err(invalid());
                    }
                }
            }
            let mut tx = app.pool.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(7878)")
                .execute(&mut *tx)
                .await?;
            let current: i32 = sqlx::query_scalar("SELECT max(version) FROM business_rule_sets")
                .fetch_one(&mut *tx)
                .await?;
            if current != version {
                return Err(ApiError(StatusCode::CONFLICT, "conflict"));
            }
            sqlx::query("INSERT INTO business_rule_sets(version,definition) VALUES($1,$2)")
                .bind(version + 1)
                .bind(definition)
                .execute(&mut *tx)
                .await?;
            db::emit(&mut tx, "business_rules.updated", Uuid::nil(), version + 1).await?;
            tx.commit().await?;
            Ok(out(json!({"version":version+1})))
        }
        ("PUT", ["dashboard", "notes"]) => {
            fields(&body, &["text", "expected_version"])?;
            let text = body["text"].as_str().ok_or_else(invalid)?;
            if text.chars().count() > 4000 || text.len() > 8192 {
                return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"));
            }
            let version = body["expected_version"]
                .as_i64()
                .filter(|v| *v >= 0 && *v < i32::MAX as i64)
                .ok_or_else(invalid)? as i32;
            let mut tx = app.pool.begin().await?;
            let saved = if version == 0 {
                sqlx::query_scalar::<_,i32>("INSERT INTO app_settings(key,value,version) VALUES('dashboard_notes',$1,1) ON CONFLICT(key) DO NOTHING RETURNING version").bind(json!({"text":text})).fetch_optional(&mut *tx).await?
            } else {
                sqlx::query_scalar::<_,i32>("UPDATE app_settings SET value=$1,version=version+1,updated_at=now() WHERE key='dashboard_notes' AND version=$2 RETURNING version").bind(json!({"text":text})).bind(version).fetch_optional(&mut *tx).await?
            };
            let saved = saved.ok_or(ApiError(StatusCode::CONFLICT, "conflict"))?;
            db::emit(&mut tx, "dashboard.notes.updated", Uuid::nil(), saved).await?;
            tx.commit().await?;
            Ok(out(json!({"text":text,"version":saved})))
        }
        ("POST", ["reports", id, "messages"]) => {
            fields(&body, &["question", "idempotency_key", "deep"])?;
            if !body["deep"].is_null() && !body["deep"].is_boolean() {
                return Err(invalid());
            }
            let q = strval(&body, "question", 2000)?;
            let key = uid(strval(&body, "idempotency_key", 36)?)?;
            let ids = create_message(
                &app,
                uid(id)?,
                q,
                key,
                body["deep"].as_bool().unwrap_or(false),
            )
            .await?;
            Ok((StatusCode::ACCEPTED, axum::Json(ids)).into_response())
        }
        ("POST", ["knowledge"]) => {
            fields(
                &body,
                &[
                    "title",
                    "kind",
                    "source",
                    "license",
                    "text",
                    "policy",
                    "service_id",
                ],
            )?;
            let title = strval(&body, "title", 240)?;
            let kind = strval(&body, "kind", 32)?;
            if !["guide", "decision_rule", "rule_explanation"].contains(&kind) {
                return Err(invalid());
            }
            let text = strval(&body, "text", 32768)?;
            if text.len() > 32768 {
                return Err(invalid());
            }
            let source = strval(&body, "source", 500)?;
            let license = strval(&body, "license", 100)?;
            let service_id = match body.get("service_id") {
                Some(Value::Null) | None => None,
                Some(value) => Some(uid(value.as_str().ok_or_else(invalid)?)?),
            };
            validate_metadata(kind, &body)?;
            let id = Uuid::new_v4();
            let mut tx = app.pool.begin().await?;
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM knowledge_documents")
                .fetch_one(&mut *tx)
                .await?;
            if n >= 200 {
                return Err(invalid());
            }
            if let Some(service_id) = service_id {
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM services WHERE id=$1)")
                        .bind(service_id)
                        .fetch_one(&mut *tx)
                        .await?;
                if !exists {
                    return Err(invalid());
                }
            }
            sqlx::query("INSERT INTO knowledge_documents(id,title,kind,source,license,service_id) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(title).bind(kind).bind(source).bind(license).bind(service_id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO knowledge_revisions(document_id,revision,text,hash,metadata) VALUES($1,1,$2,$3,$4)").bind(id).bind(text).bind(hash(text)).bind(json!({"policy":body["policy"]})).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(out(json!({"id":id,"revision":1})))
        }
        ("PUT", ["knowledge", id, "draft"]) => {
            fields(&body, &["expected_version", "text", "policy", "service_id"])?;
            let text = strval(&body, "text", 32768)?;
            if text.len() > 32768 {
                return Err(invalid());
            }
            let id = uid(id)?;
            let mut tx = app.pool.begin().await?;
            let kind: String =
                sqlx::query_scalar("SELECT kind FROM knowledge_documents WHERE id=$1 FOR UPDATE")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?;
            validate_metadata(&kind, &body)?;
            let version: i32 = sqlx::query_scalar(
                "SELECT max(revision) FROM knowledge_revisions WHERE document_id=$1",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if body["expected_version"] != version {
                return Err(ApiError(StatusCode::CONFLICT, "conflict"));
            }
            if let Some(value) = body.get("service_id") {
                let service_id = match value {
                    Value::Null => None,
                    value => Some(uid(value.as_str().ok_or_else(invalid)?)?),
                };
                if let Some(service_id) = service_id {
                    let exists: bool =
                        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM services WHERE id=$1)")
                            .bind(service_id)
                            .fetch_one(&mut *tx)
                            .await?;
                    if !exists {
                        return Err(invalid());
                    }
                }
                sqlx::query("UPDATE knowledge_documents SET service_id=$2 WHERE id=$1")
                    .bind(id)
                    .bind(service_id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("INSERT INTO knowledge_revisions(document_id,revision,text,hash,metadata) VALUES($1,$2,$3,$4,$5)").bind(id).bind(version+1).bind(text).bind(hash(text)).bind(json!({"policy":body["policy"]})).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(out(json!({"id":id,"revision":version+1})))
        }
        ("POST", ["knowledge", "builds"]) => {
            fields(&body, &["manifest", "idempotency_key"])?;
            let id = knowledge::create_build(
                &app,
                &body["manifest"],
                uid(strval(&body, "idempotency_key", 36)?)?,
            )
            .await?;
            Ok((StatusCode::ACCEPTED, axum::Json(json!({"build_id":id}))).into_response())
        }
        ("PUT", ["knowledge", "active"]) => {
            fields(&body, &["corpus_id", "expected_version"])?;
            let id = uid(strval(&body, "corpus_id", 36)?)?;
            let version = body["expected_version"].as_i64().ok_or_else(invalid)? as i32;
            let mut tx = app.pool.begin().await?;
            let policy:Option<Uuid>=sqlx::query_scalar("SELECT policy_set_id FROM corpus_versions WHERE id=$1 AND state='ready' AND embedding_model_revision=$2").bind(id).bind(MODEL_REV).fetch_optional(&mut *tx).await?;
            let policy = policy.ok_or(ApiError(StatusCode::CONFLICT, "conflict"))?;
            let affected=sqlx::query("UPDATE knowledge_state SET active_corpus_id=$1,active_policy_version=$2,version=version+1 WHERE singleton AND version=$3").bind(id).bind(policy).bind(version).execute(&mut *tx).await?.rows_affected();
            if affected != 1 {
                return Err(ApiError(StatusCode::CONFLICT, "conflict"));
            }
            db::emit(&mut tx, "knowledge.activated", id, version + 1).await?;
            tx.commit().await?;
            Ok(out(json!({"corpus_id":id,"version":version+1})))
        }
        ("PUT", ["settings", "ai"]) => save_settings(&app, &body).await,
        ("POST", ["settings", "ai", "check"]) => check_ai_connection(&app, &body).await,
        ("PUT", ["settings", "spend-limit"]) => save_spend_limit(&app, &body).await,
        ("POST", ["services", "mcp", "check"]) => check_mcp_connection(&app, &body).await,
        ("POST", ["settings", "lab", "check"]) => check_mcp_connection(&app, &body).await,
        ("PUT", ["settings", "cve"]) => {
            fields(&body, &["enabled", "expected_version"])?;
            Ok(out(crate::cve::save_settings(&app, &body).await?))
        }
        _ => Err(ApiError(StatusCode::NOT_FOUND, "not_found")),
    }
}
fn validate_metadata(kind: &str, body: &Value) -> Result<()> {
    if kind == "decision_rule" {
        let p: contracts::Policy =
            serde_json::from_value(body["policy"].clone()).map_err(|_| invalid())?;
        contracts::validate_policy(&p)?;
    } else if !body["policy"].is_null() {
        return Err(invalid());
    }
    Ok(())
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |x, (a, b)| x | (a ^ b)) == 0
}
fn filter_hash(path: &str, q: &HashMap<String, String>) -> String {
    let mut sorted = q
        .iter()
        .filter(|(k, _)| k.as_str() != "cursor" && k.as_str() != "limit")
        .collect::<Vec<_>>();
    sorted.sort();
    hash(format!("{path}:{sorted:?}"))
}
fn cursor_encode(n: i64, path: &str, q: &HashMap<String, String>) -> String {
    URL_SAFE_NO_PAD.encode(json!({"n":n,"filters":filter_hash(path,q)}).to_string())
}
fn page(q: &HashMap<String, String>, path: &str, allowed: &[&str]) -> Result<(i64, Option<i64>)> {
    if q.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid());
    }
    let limit = q
        .get("limit")
        .map(|s| s.parse::<i64>())
        .transpose()
        .map_err(|_| invalid())?
        .unwrap_or(25);
    if !(1..=100).contains(&limit) {
        return Err(invalid());
    }
    let cursor = if let Some(c) = q.get("cursor") {
        let bytes = URL_SAFE_NO_PAD.decode(c).map_err(|_| invalid())?;
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if v["filters"] != filter_hash(path, q) {
            return Err(invalid());
        }
        let n = v["n"].as_i64().ok_or_else(invalid)?;
        if n < 0 {
            return Err(invalid());
        }
        Some(n)
    } else {
        None
    };
    Ok((limit, cursor))
}
fn paginate(
    mut rows: Vec<Value>,
    limit: i64,
    key: &str,
    path: &str,
    q: &HashMap<String, String>,
) -> Value {
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        Some(cursor_encode(
            rows.last().and_then(|r| r[key].as_i64()).unwrap_or(limit),
            path,
            q,
        ))
    } else {
        None
    };
    json!({"items":rows,"next_cursor":next})
}
async fn reports(app: &App, q: &HashMap<String, String>) -> Result<Value> {
    let path = "/api/v1/reports";
    let (limit, cursor) = page(
        q,
        path,
        &[
            "limit",
            "cursor",
            "severity",
            "rule_id",
            "analysis_state",
            "origin",
            "run_id",
            "service",
            "service_id",
            "from",
            "to",
        ],
    )?;
    for (key, valid) in [
        (
            "severity",
            vec!["low", "medium", "high", "critical", "informational"],
        ),
        ("rule_id", vec!["R1", "R2", "R3", "R4", "AI"]),
        ("origin", vec!["mock", "live", "cache"]),
        (
            "analysis_state",
            vec![
                "pending",
                "eligible",
                "preparing",
                "reserved",
                "in_flight",
                "succeeded",
                "failed",
                "unknown",
                "cached",
                "skipped_budget",
                "blocked_config",
            ],
        ),
    ] {
        if q.get(key).is_some_and(|v| !valid.contains(&v.as_str())) {
            return Err(invalid());
        }
    }
    let run = q.get("run_id").map(|s| uid(s)).transpose()?;
    let from = date(q, "from")?;
    let to = date(q, "to")?;
    let cursor_id = if let Some(c) = q.get("cursor") {
        let v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(c).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        Some(uid(v["id"].as_str().ok_or_else(invalid)?)?)
    } else {
        None
    };
    let cursor_time = cursor
        .map(|n| chrono::DateTime::<Utc>::from_timestamp_micros(n).ok_or_else(invalid))
        .transpose()?;
    let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(t) FROM (SELECT (SELECT coalesce(jsonb_agg(jsonb_build_object('id',s.id,'name',s.name,'enabled',s.enabled,'deleted_at',s.deleted_at) ORDER BY s.id),'[]') FROM incident_services ss JOIN services s ON s.id=ss.service_id WHERE ss.incident_id=i.id) AS services,i.id,i.run_id,i.rule_id,i.rule_version,i.detection_origin,coalesce(i.deterministic_reason->>'classification',(SELECT c.classification FROM incident_events ie JOIN event_classifications c ON c.event_id=ie.event_id WHERE ie.incident_id=i.id ORDER BY (ie.role='trigger') DESC,c.created_at DESC LIMIT 1)) AS classification,coalesce(i.deterministic_reason->>'normalized_path',i.deterministic_reason->>'classification_path') AS classification_path,i.severity,i.title,coalesce((SELECT string_agg(DISTINCT s.name, ', ' ORDER BY s.name) FROM incident_services ss JOIN services s ON s.id=ss.service_id WHERE ss.incident_id=i.id),i.group_key->>'service') AS service,i.opened_at,i.last_match_at,i.evidence_version,i.report_version AS version,(SELECT count(*) FROM (SELECT event_id AS id FROM incident_events WHERE incident_id=i.id UNION SELECT s.record_id AS id FROM finding_segments fs JOIN review_findings f ON f.id=fs.finding_id JOIN review_segments s ON s.id=fs.segment_id WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND EXISTS(SELECT 1 FROM record_incidents ri WHERE ri.incident_id=i.id AND ri.record_id=s.record_id)) evidence_records) AS evidence_count,(SELECT jsonb_build_object('state',j.state,'reason',j.reason,'origin',a.origin,'provider',j.provider,'kind',j.kind,'evidence_version',j.evidence_version,'summary',CASE WHEN j.kind='review' THEN (SELECT to_jsonb(f.payload->>'reason') FROM review_findings f WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND f.job_id=j.id ORDER BY f.created_at DESC,f.id DESC LIMIT 1) ELSE a.response->'summary' END) FROM analysis_jobs j LEFT JOIN analyses a ON a.job_id=j.id WHERE (j.kind='analysis' AND j.incident_id=i.id) OR (j.kind='review' AND EXISTS(SELECT 1 FROM review_findings f WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND f.job_id=j.id)) ORDER BY j.created_at DESC,j.id DESC LIMIT 1) AS analysis FROM incidents i WHERE NOT i.historical_group AND ($1::text IS NULL OR i.severity=$1) AND ($2::text IS NULL OR i.rule_id=$2) AND ($3::uuid IS NULL OR i.run_id=$3) AND ($4::timestamptz IS NULL OR i.opened_at>=$4) AND ($5::timestamptz IS NULL OR i.opened_at<=$5) AND ($6::text IS NULL OR EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.state=$6 AND ((j.kind='analysis' AND j.incident_id=i.id) OR (j.kind='review' AND EXISTS(SELECT 1 FROM review_findings f WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND f.job_id=j.id))))) AND ($7::text IS NULL OR EXISTS(SELECT 1 FROM analyses a JOIN analysis_jobs j ON j.id=a.job_id WHERE a.origin=$7 AND ((j.kind='analysis' AND j.incident_id=i.id) OR (j.kind='review' AND EXISTS(SELECT 1 FROM review_findings f WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND f.job_id=j.id))))) AND ($9::timestamptz IS NULL OR (i.opened_at,i.id)<($9,$10)) AND ($11::text IS NULL OR EXISTS(SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE ie.incident_id=i.id AND e.service=$11) OR ($11::text IS NOT NULL AND i.group_key->>'service'=$11)) AND ($12::uuid IS NULL OR EXISTS(SELECT 1 FROM incident_services ss WHERE ss.incident_id=i.id AND ss.service_id=$12)) ORDER BY i.opened_at DESC,i.id DESC LIMIT $8)t").bind(q.get("severity")).bind(q.get("rule_id")).bind(run).bind(from).bind(to).bind(q.get("analysis_state")).bind(q.get("origin")).bind(limit+1).bind(cursor_time).bind(cursor_id).bind(q.get("service")).bind(q.get("service_id").map(|s|uid(s)).transpose()?).fetch_all(&app.pool).await?;
    let last = rows.get((limit - 1) as usize).cloned();
    let mut p = paginate(rows, limit, "", path, q);
    if p["next_cursor"].is_string() {
        let last = last.ok_or_else(invalid)?;
        let t: chrono::DateTime<Utc> = last["opened_at"]
            .as_str()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        p["next_cursor"] = json!(
            URL_SAFE_NO_PAD.encode(
                json!({"n":t.timestamp_micros(),"id":last["id"],"filters":filter_hash(path,q)})
                    .to_string()
            )
        );
    }
    p["total_count"]=json!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM incidents i WHERE NOT i.historical_group AND ($1::text IS NULL OR i.severity=$1) AND ($2::text IS NULL OR i.rule_id=$2) AND ($3::uuid IS NULL OR i.run_id=$3) AND ($4::timestamptz IS NULL OR i.opened_at>=$4) AND ($5::timestamptz IS NULL OR i.opened_at<=$5) AND ($6::text IS NULL OR EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.state=$6 AND ((j.kind='analysis' AND j.incident_id=i.id) OR (j.kind='review' AND EXISTS(SELECT 1 FROM review_findings f WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND f.job_id=j.id))))) AND ($7::text IS NULL OR EXISTS(SELECT 1 FROM analyses a JOIN analysis_jobs j ON j.id=a.job_id WHERE a.origin=$7 AND ((j.kind='analysis' AND j.incident_id=i.id) OR (j.kind='review' AND EXISTS(SELECT 1 FROM review_findings f WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND f.job_id=j.id))))) AND ($8::text IS NULL OR EXISTS(SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE ie.incident_id=i.id AND e.service=$8) OR ($8::text IS NOT NULL AND i.group_key->>'service'=$8)) AND ($9::uuid IS NULL OR EXISTS(SELECT 1 FROM incident_services ss WHERE ss.incident_id=i.id AND ss.service_id=$9))").bind(q.get("severity")).bind(q.get("rule_id")).bind(run).bind(from).bind(to).bind(q.get("analysis_state")).bind(q.get("origin")).bind(q.get("service")).bind(q.get("service_id").map(|s|uid(s)).transpose()?).fetch_one(&app.pool).await?);
    p["available_runs"]=json!(sqlx::query_scalar::<_,Uuid>("SELECT run_id FROM events GROUP BY run_id ORDER BY max(ingested_at) DESC,run_id DESC LIMIT 100").fetch_all(&app.pool).await?);
    p["available_services"] = services::list(
        app,
        &HashMap::from([
            ("state".into(), "all".into()),
            ("limit".into(), "25".into()),
        ]),
    )
    .await?["items"]
        .clone();
    p["available_batches"]=json!(sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('id',run_id,'downloaded',bool_or(parser!='sentinel-json'),'events',count(*),'received_at',min(ingested_at)) FROM events GROUP BY run_id ORDER BY max(ingested_at) DESC LIMIT 100").fetch_all(&app.pool).await?);
    Ok(p)
}
fn date(q: &HashMap<String, String>, k: &str) -> Result<Option<chrono::DateTime<Utc>>> {
    q.get(k)
        .map(|s| s.parse().map_err(|_| invalid()))
        .transpose()
}
async fn report(app: &App, id: Uuid) -> Result<Value> {
    let mut r:Value=sqlx::query_scalar("SELECT to_jsonb(i)||jsonb_build_object('services',(SELECT coalesce(jsonb_agg(jsonb_build_object('id',s.id,'name',s.name,'enabled',s.enabled,'deleted_at',s.deleted_at) ORDER BY s.id),'[]') FROM incident_services ss JOIN services s ON s.id=ss.service_id WHERE ss.incident_id=i.id),'version',report_version,'evidence_count',(SELECT count(*) FROM (SELECT event_id AS id FROM incident_events WHERE incident_id=i.id UNION SELECT s.record_id AS id FROM finding_segments fs JOIN review_findings f ON f.id=fs.finding_id JOIN review_segments s ON s.id=fs.segment_id WHERE EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=i.id) AND EXISTS(SELECT 1 FROM record_incidents ri WHERE ri.incident_id=i.id AND ri.record_id=s.record_id)) evidence_records),'service',coalesce((SELECT string_agg(DISTINCT s.name, ', ' ORDER BY s.name) FROM incident_services ss JOIN services s ON s.id=ss.service_id WHERE ss.incident_id=i.id),i.group_key->>'service'),'related_incident_ids',(SELECT coalesce(jsonb_agg(to_id),'[]') FROM incident_relations WHERE from_id=i.id)) FROM incidents i WHERE id=$1").bind(id).fetch_one(&app.pool).await?;
    r["analysis_revisions"]=json!(sqlx::query_scalar::<_,Value>("SELECT to_jsonb(j)||jsonb_build_object('analysis',(SELECT to_jsonb(a) FROM analyses a WHERE a.job_id=j.id AND a.origin<>'mock'),'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]') FROM analysis_attempts t WHERE t.job_id=j.id)) FROM analysis_jobs j WHERE incident_id=$1 AND kind='analysis' ORDER BY created_at DESC").bind(id).fetch_all(&app.pool).await?);
    r["followup_actions"] = json!(
        sqlx::query_scalar::<_, Value>(
            "SELECT to_jsonb(a) FROM incident_actions a WHERE incident_id=$1 ORDER BY id"
        )
        .bind(id)
        .fetch_all(&app.pool)
        .await?
    );
    r["findings"]=json!(sqlx::query_scalar::<_,Value>("SELECT to_jsonb(f)||jsonb_build_object('origin',a.origin,'snapshot',j.snapshot,'job',to_jsonb(j),'knowledge_references',a.response->'knowledge_references','segments',(SELECT jsonb_agg(jsonb_build_object('id',s.id,'record_id',s.record_id,'start',s.byte_start,'end',s.byte_end,'text',s.content,'hash',s.content_hash)) FROM finding_segments fs JOIN review_segments s ON s.id=fs.segment_id WHERE fs.finding_id=f.id AND (EXISTS(SELECT 1 FROM record_incidents ri2 WHERE ri2.incident_id=$1 AND ri2.record_id=s.record_id) OR EXISTS(SELECT 1 FROM incidents old WHERE old.id=$1 AND old.historical_group)))) FROM review_findings f JOIN analysis_jobs j ON j.id=f.job_id JOIN analyses a ON a.job_id=j.id WHERE a.origin<>'mock' AND (EXISTS(SELECT 1 FROM incident_finding_records fl JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE fl.finding_id=f.id AND ri.incident_id=$1) OR (f.incident_id=$1 AND EXISTS(SELECT 1 FROM incidents old WHERE old.id=$1 AND old.historical_group))) ORDER BY f.created_at DESC").bind(id).fetch_all(&app.pool).await?);
    Ok(r)
}
async fn events(app: &App, q: &HashMap<String, String>, incident: Option<Uuid>) -> Result<Value> {
    if let Some(id) = incident {
        let ai: bool =
            sqlx::query_scalar("SELECT detection_origin='ai' FROM incidents WHERE id=$1")
                .bind(id)
                .fetch_one(&app.pool)
                .await?;
        if ai {
            let (limit, cursor) = page(
                q,
                &format!("/api/v1/reports/{id}/evidence"),
                &["cursor", "limit"],
            )?;
            let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',s.id,'record_id',r.id,'ingest_seq',s.segment_seq,'event_type','text.record','message',s.content,'parser',r.parser,'source','synthetic','service_id',r.service_id,'service',coalesce((SELECT name FROM services WHERE id=r.service_id),r.service),'event_time',r.event_time,'ingested_at',r.received_at,'selected_for_analysis',true,'range',jsonb_build_array(s.byte_start,s.byte_end),'hash',s.content_hash) FROM review_segments s JOIN text_records r ON r.id=s.record_id WHERE EXISTS(SELECT 1 FROM finding_segments fs JOIN review_findings f ON f.id=fs.finding_id JOIN incident_finding_records fl ON fl.finding_id=f.id AND fl.record_id=s.record_id JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE ri.incident_id=$1 AND fs.segment_id=s.id) AND ($2::bigint IS NULL OR s.segment_seq<$2) ORDER BY s.segment_seq DESC LIMIT $3").bind(id).bind(cursor).bind(limit+1).fetch_all(&app.pool).await?;
            return Ok(paginate(
                rows,
                limit,
                "ingest_seq",
                &format!("/api/v1/reports/{id}/evidence"),
                q,
            ));
        }
    }
    let path = incident
        .map(|id| format!("/api/v1/reports/{id}/evidence"))
        .unwrap_or("/api/v1/events".into());
    let (limit, cursor) = page(
        q,
        &path,
        &[
            "limit",
            "cursor",
            "run_id",
            "source",
            "event_type",
            "service_id",
            "from",
            "to",
        ],
    )?;
    let run = q.get("run_id").map(|s| uid(s)).transpose()?;
    if q.get("source")
        .is_some_and(|s| !["auth", "app", "system"].contains(&s.as_str()))
        || q.get("event_type").is_some_and(|s| {
            !["auth.failed", "auth.success", "app.error", "system.notice"].contains(&s.as_str())
        })
    {
        return Err(invalid());
    }
    let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(e)-'line_hash'-'file_instance_id'-'byte_start'-'byte_end'||jsonb_build_object('service',coalesce((SELECT name FROM services WHERE id=e.service_id),e.service),'classification',(SELECT c.classification FROM event_classifications c WHERE c.event_id=e.id),'classification_reason',(SELECT c.reason FROM event_classifications c WHERE c.event_id=e.id),'selected_for_analysis',EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.incident_id=$1 AND j.snapshot->'events' @> jsonb_build_array(jsonb_build_object('id',e.id)))) FROM events e WHERE ($1::uuid IS NULL OR EXISTS(SELECT 1 FROM incident_events ie WHERE ie.incident_id=$1 AND ie.event_id=e.id)) AND ($2::bigint IS NULL OR e.ingest_seq<$2) AND ($3::uuid IS NULL OR e.run_id=$3) AND ($4::text IS NULL OR e.source=$4) AND ($5::text IS NULL OR e.event_type=$5) AND ($6::timestamptz IS NULL OR e.event_time>=$6) AND ($7::timestamptz IS NULL OR e.event_time<=$7) AND ($9::uuid IS NULL OR e.service_id=$9) ORDER BY e.ingest_seq DESC LIMIT $8").bind(incident).bind(cursor).bind(run).bind(q.get("source")).bind(q.get("event_type")).bind(date(q,"from")?).bind(date(q,"to")?).bind(limit+1).bind(q.get("service_id").map(|s|uid(s)).transpose()?).fetch_all(&app.pool).await?;
    let mut p = paginate(rows, limit, "ingest_seq", &path, q);
    p["total_count"]=json!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM events e WHERE ($1::uuid IS NULL OR EXISTS(SELECT 1 FROM incident_events ie WHERE ie.incident_id=$1 AND ie.event_id=e.id)) AND ($2::uuid IS NULL OR e.run_id=$2) AND ($3::text IS NULL OR e.source=$3) AND ($4::text IS NULL OR e.event_type=$4) AND ($5::timestamptz IS NULL OR e.event_time>=$5) AND ($6::timestamptz IS NULL OR e.event_time<=$6) AND ($7::uuid IS NULL OR e.service_id=$7)").bind(incident).bind(run).bind(q.get("source")).bind(q.get("event_type")).bind(date(q,"from")?).bind(date(q,"to")?).bind(q.get("service_id").map(|s|uid(s)).transpose()?).fetch_one(&app.pool).await?);

    Ok(p)
}
async fn create_message(
    app: &App,
    incident: Uuid,
    q: &str,
    key: Uuid,
    deep: bool,
) -> Result<Value> {
    let mut tx = app.pool.begin().await?;
    services::lock(&mut tx).await?;
    let ev: i32 =
        sqlx::query_scalar("SELECT evidence_version FROM incidents WHERE id=$1 FOR UPDATE")
            .bind(incident)
            .fetch_one(&mut *tx)
            .await?;
    let conv = Uuid::new_v5(&incident, b"conversation");
    sqlx::query("INSERT INTO conversations(id,incident_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(conv)
        .bind(incident)
        .execute(&mut *tx)
        .await?;
    let ph = if deep {
        hash(format!("deep:{q}"))
    } else {
        hash(q)
    };
    if let Some(m)=sqlx::query("SELECT m.id,m.payload_hash,j.id AS job_id FROM messages m JOIN analysis_jobs j ON j.message_id=m.id WHERE conversation_id=$1 AND idempotency_key=$2").bind(conv).bind(key).fetch_optional(&mut *tx).await?{if m.get::<String,_>("payload_hash")!=ph{return Err(ApiError(StatusCode::CONFLICT,"conflict"));}return Ok(json!({"message_id":m.get::<Uuid,_>("id"),"job_id":m.get::<Uuid,_>("job_id")}));}
    if gateway::generation_paused() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "generation_paused",
        ));
    }
    let active = sqlx::query("SELECT * FROM knowledge_state")
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
        ))?;
    let settings = sqlx::query("SELECT * FROM app_settings WHERE key='ai'")
        .fetch_one(&mut *tx)
        .await?;
    let p: Value = settings.get("value");
    let rule: String = sqlx::query_scalar("SELECT rule_id FROM incidents WHERE id=$1")
        .bind(incident)
        .fetch_one(&mut *tx)
        .await?;
    let route = gateway::route(&p, settings.get("version"), "chat", &rule, deep);
    let mid = Uuid::new_v4();
    let jid = Uuid::new_v4();
    sqlx::query("INSERT INTO messages(id,conversation_id,ordinal,role,content,state,evidence_version,request_id,idempotency_key,payload_hash) VALUES($1,$2,(SELECT coalesce(max(ordinal),0)+1 FROM messages WHERE conversation_id=$2),'user',$3,'pending',$4,$5,$6,$7)").bind(mid).bind(conv).bind(json!({"question":contracts::redact(q,&app.config.session_id)})).bind(ev).bind(Uuid::new_v4()).bind(key).bind(ph).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO analysis_jobs(id,kind,incident_id,message_id,evidence_version,provider_profile_version,provider,model,corpus_version,policy_version,snapshot_hash,snapshot,state,route,prompt_version) VALUES($1,'chat',$2,$3,$4,$5,$6,$7,$8,$9,'','{}','pending',$10,$11)").bind(jid).bind(incident).bind(mid).bind(ev).bind(settings.get::<i32,_>("version")).bind(route["provider"].as_str().unwrap_or("mock")).bind(route["model"].as_str().unwrap_or("mock-v1")).bind(active.get::<Uuid,_>("active_corpus_id")).bind(active.get::<Uuid,_>("active_policy_version")).bind(&route).bind(provider::PROMPT_VERSION).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO job_services(job_id,service_id,service_version) SELECT $1,s.id,s.version FROM incident_services i JOIN services s ON s.id=i.service_id WHERE i.incident_id=$2 ON CONFLICT DO NOTHING").bind(jid).bind(incident).execute(&mut *tx).await?;
    db::emit(&mut tx, "conversation.updated", incident, ev).await?;
    tx.commit().await?;
    Ok(json!({"message_id":mid,"job_id":jid}))
}
async fn settings(app: &App) -> Result<Value> {
    let r = sqlx::query("SELECT value,version FROM app_settings WHERE key='ai'")
        .fetch_one(&app.pool)
        .await?;
    let persisted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM provider_credentials)")
        .fetch_one(&app.pool)
        .await?;
    let has_volatile = app.volatile_key.lock().await.is_some();
    let authorization = app
        .authorization
        .lock()
        .await
        .clone()
        .filter(|p| p.expires_at > chrono::Utc::now());
    Ok(
        json!({"profile":r.get::<Value,_>("value"),"version":r.get::<i32,_>("version"),"has_key":persisted||has_volatile,"credential_storage":if app.config.master_key.is_some(){"AES-256-GCM"}else{"volatile"},"authorization":authorization,"live_block_reason":"El perfil configurado procesa trabajos elegibles automáticamente. El límite monetario de sesión se configura por separado.","catalog":provider::catalog()}),
    )
}
fn usd_units(value: &str) -> Result<i64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || whole.len() > 7
        || !whole.bytes().all(|c| c.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(invalid());
    }
    let dollars = whole.parse::<i64>().map_err(|_| invalid())?;
    let cents = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<i64>().map_err(|_| invalid())? * 10,
        _ => fraction.parse::<i64>().map_err(|_| invalid())?,
    };
    let total = dollars
        .checked_mul(100)
        .and_then(|n| n.checked_add(cents))
        .ok_or_else(invalid)?;
    if !(1..=100_000_000).contains(&total) {
        return Err(invalid());
    }
    Ok(total * 1_000_000)
}
async fn save_spend_limit(app: &App, v: &Value) -> Result<Response> {
    fields(v, &["enabled", "amount_usd", "expected_version"])?;
    let enabled = v["enabled"].as_bool().ok_or_else(invalid)?;
    let version = v["expected_version"]
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .ok_or_else(invalid)?;
    let amount = if enabled {
        usd_units(v["amount_usd"].as_str().ok_or_else(invalid)?)?
    } else {
        0
    };
    let mut tx = app.pool.begin().await?;
    let row = sqlx::query("SELECT cap_version,reserved_units FROM budget_accounts WHERE scope='session' AND scope_key=$1 FOR UPDATE")
        .bind(&app.config.session_id)
        .fetch_one(&mut *tx)
        .await?;
    if row.get::<i32, _>("cap_version") != version {
        return Err(ApiError(StatusCode::CONFLICT, "conflict"));
    }
    if enabled && row.get::<i64, _>("reserved_units") > 0 {
        return Err(ApiError(StatusCode::CONFLICT, "spend_limit_in_flight"));
    }
    sqlx::query("UPDATE budget_accounts SET cap_baseline_spent_units=CASE WHEN $2 AND NOT cap_enabled THEN spent_units ELSE cap_baseline_spent_units END,cap_enabled=$2,limit_units=CASE WHEN $2 THEN $3 ELSE limit_units END,cap_version=cap_version+1 WHERE scope='session' AND scope_key=$1")
        .bind(&app.config.session_id)
        .bind(enabled)
        .bind(amount)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE analysis_jobs j SET state='pending',reason='session_limit_changed',eligible_at=now() WHERE j.kind<>'chat' AND j.state='skipped_budget' AND j.reason='session_limit_reached' AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id)")
        .execute(&mut *tx)
        .await?;
    db::emit(&mut tx, "budget.updated", Uuid::nil(), version + 1).await?;
    tx.commit().await?;
    let saved: Value = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM budget_accounts a WHERE scope='session' AND scope_key=$1",
    )
    .bind(&app.config.session_id)
    .fetch_one(&app.pool)
    .await?;
    Ok(out(saved))
}
async fn check_mcp_connection(_app: &App, v: &Value) -> Result<Response> {
    fields(v, &["endpoint", "credential", "ca_pem"])?;
    let endpoint = strval(v, "endpoint", 200)?;
    let credential = strval(v, "credential", 4096)?;
    if endpoint.len() > 200
        || endpoint.contains(['\0', '\r', '\n'])
        || credential.len() > 4096
        || credential.contains(['\0', '\r', '\n'])
    {
        return Err(invalid());
    }
    if mcp::lab_endpoint_shape(endpoint).is_err() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "mcp_lab_destination_denied",
        ));
    }
    let ca_error = || ApiError(StatusCode::BAD_REQUEST, "mcp_lab_ca_invalid");
    let ca_pem: Option<&str> = match v.get("ca_pem") {
        Some(Value::String(pem)) => {
            if pem.is_empty() {
                None
            } else {
                if pem.len() > 16384 || reqwest::Certificate::from_pem(pem.as_bytes()).is_err() {
                    return Err(ca_error());
                }
                Some(pem.as_str())
            }
        }
        Some(Value::Null) | None => None,
        Some(_) => return Err(ca_error()),
    };
    let resources = mcp::probe_lab_connection(endpoint, credential, ca_pem)
        .await
        .map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "mcp_lab_probe_failed"))?;
    Ok(out(json!({"resources": resources})))
}

async fn save_settings(app: &App, v: &Value) -> Result<Response> {
    fields(
        v,
        &[
            "expected_version",
            "name",
            "provider",
            "base_url",
            "model",
            "mode",
            "json_mode",
            "api_key",
            "deep_model",
            "deep_profile",
            "deep_api_key",
            "models",
            "drafts",
            "workspace_id",
        ],
    )?;
    let name = strval(v, "name", 100)?;
    let provider = strval(v, "provider", 64)?;
    let base = strval(v, "base_url", 500)?;
    provider::validate_preset(provider, base)?;
    let model = v["model"].as_str().unwrap_or("");
    if model.len() > 100 || model.contains(['\0', '\r', '\n']) {
        return Err(invalid());
    }
    let mode = strval(v, "mode", 8)?;
    if !["live", "draft", "disabled"].contains(&mode)
        || !["openai", "deepseek", "gemini", "claude", "compatible"].contains(&provider)
        || !v["json_mode"].is_boolean()
    {
        return Err(invalid());
    }
    if mode == "live" && model.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "model_spec_missing"));
    }
    let deep_model = v["deep_model"].as_str().unwrap_or("");
    if deep_model.len() > 100 {
        return Err(invalid());
    }
    let workspace_id = v.get("workspace_id").and_then(Value::as_str).unwrap_or("");
    if workspace_id.len() > 100
        || workspace_id.contains(['\0', '\r', '\n'])
        || (!workspace_id.is_empty() && provider != "claude")
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "workspace_id_invalid"));
    }
    let models = v.get("models").cloned().unwrap_or(json!({}));
    validate_models(&models, provider)?;
    // Un perfil live recién habilitado no puede quedar con spec:null: el
    // modelo estándar y el profundo, si se usan, deben tener ficha válida.
    if mode == "live" {
        for selected in [model, deep_model].into_iter().filter(|m| !m.is_empty()) {
            let Some(spec) = models.get(selected) else {
                return Err(ApiError(StatusCode::BAD_REQUEST, "model_spec_missing"));
            };
            let parsed: provider::ModelSpec =
                serde_json::from_value(spec.clone()).map_err(|_| invalid())?;
            parsed
                .validate(provider)
                .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "model_spec_missing"))?;
        }
    }
    let drafts = v.get("drafts").cloned().unwrap_or(json!({}));
    if drafts.as_object().is_none() || drafts.to_string().len() > 20_000 {
        return Err(invalid());
    }
    let deep_profile = v.get("deep_profile").filter(|p| !p.is_null()).cloned();
    if let Some(p) = &deep_profile {
        fields(
            p,
            &["provider", "base_url", "model", "models", "workspace_id"],
        )?;
        let deep_provider = strval(p, "provider", 64)?;
        provider::validate_preset(deep_provider, strval(p, "base_url", 500)?)?;
        strval(p, "model", 100)?;
        let deep_workspace = p.get("workspace_id").and_then(Value::as_str).unwrap_or("");
        if deep_workspace.len() > 100
            || deep_workspace.contains(['\0', '\r', '\n'])
            || (!deep_workspace.is_empty() && deep_provider != "claude")
        {
            return Err(ApiError(StatusCode::BAD_REQUEST, "workspace_id_invalid"));
        }
        validate_models(&p["models"], deep_provider)?;
        if app.config.master_key.is_none() {
            return Err(invalid());
        }
    }
    let mut authorization = app.authorization.lock().await;
    let mut tx = app.pool.begin().await?;
    let row = sqlx::query("SELECT value,version FROM app_settings WHERE key='ai' FOR UPDATE")
        .fetch_one(&mut *tx)
        .await?;
    let version: i32 = row.get("version");
    if v["expected_version"] != version {
        return Err(ApiError(StatusCode::CONFLICT, "conflict"));
    }
    let id = uid(row.get::<Value, _>("value")["id"].as_str().unwrap())?;
    let p = json!({"id":id,"name":name,"provider":provider,"base_url":base,"model":model,"mode":mode,"json_mode":v["json_mode"],"deep_model":deep_model,"deep_profile":deep_profile,"models":models,"drafts":drafts,"workspace_id":workspace_id});
    sqlx::query(
        "UPDATE app_settings SET value=$1,version=version+1,updated_at=now() WHERE key='ai'",
    )
    .bind(&p)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO provider_profiles(id,version,profile) VALUES($1,$2,$3)")
        .bind(id)
        .bind(version + 1)
        .bind(p)
        .execute(&mut *tx)
        .await?;
    // Copy the credential to the new immutable profile version before accepting rotation.
    sqlx::query("INSERT INTO credential_versions(profile_id,version,ciphertext,nonce) SELECT profile_id,$2,ciphertext,nonce FROM credential_versions WHERE profile_id IN($1,$3) AND version=$4 ON CONFLICT DO NOTHING").bind(id).bind(version+1).bind(Uuid::new_v5(&id,b"deep")).bind(version).execute(&mut *tx).await?;
    let mut volatile = None;
    if let Some(key) = v["api_key"].as_str().filter(|k| !k.is_empty()) {
        if key.len() > 512 {
            return Err(invalid());
        }
        if let Some(master) = &app.config.master_key {
            let (cipher, nonce) = encrypt(master, key)?;
            sqlx::query("INSERT INTO credential_versions VALUES($1,$2,$3,$4) ON CONFLICT(profile_id,version) DO UPDATE SET ciphertext=$3,nonce=$4").bind(id).bind(version+1).bind(&cipher).bind(&nonce).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO provider_credentials VALUES($1,$2,$3) ON CONFLICT(profile_id) DO UPDATE SET ciphertext=$2,nonce=$3").bind(id).bind(cipher).bind(nonce).execute(&mut *tx).await?;
        } else {
            volatile = Some(key.to_string());
        }
    }
    if let Some(key) = v["deep_api_key"].as_str().filter(|s| !s.is_empty()) {
        if key.len() > 512 {
            return Err(invalid());
        }
        let (cipher, nonce) = encrypt(app.config.master_key.as_ref().ok_or_else(invalid)?, key)?;
        sqlx::query("INSERT INTO credential_versions VALUES($1,$2,$3,$4) ON CONFLICT(profile_id,version) DO UPDATE SET ciphertext=$3,nonce=$4").bind(Uuid::new_v5(&id,b"deep")).bind(version+1).bind(cipher).bind(nonce).execute(&mut *tx).await?;
    }
    db::emit(&mut tx, "settings.updated", id, version + 1).await?;
    tx.commit().await?;
    if volatile.is_some() {
        *app.volatile_key.lock().await = volatile;
    }
    *authorization = None;
    drop(authorization);
    Ok(out(settings(app).await?))
}
/// Ajustes → «Probar conexión»: diagnostica el proveedor con los valores del
/// formulario (o la credencial guardada si el campo de clave viene vacío)
/// mediante un único `GET /models`. No genera contenido, no crea trabajos y
/// no consume tokens; el resultado se devuelve como diagnóstico, no como
/// error HTTP, para que la UI pinte el estado exacto.
async fn check_ai_connection(app: &App, v: &Value) -> Result<Response> {
    fields(
        v,
        &["provider", "base_url", "model", "api_key", "workspace_id"],
    )?;
    let provider = strval(v, "provider", 64)?;
    let base = strval(v, "base_url", 500)?;
    let model = v["model"].as_str().unwrap_or("");
    if model.len() > 100 || model.contains(['\0', '\r', '\n']) {
        return Err(invalid());
    }
    let workspace_id = v.get("workspace_id").and_then(Value::as_str).unwrap_or("");
    if workspace_id.len() > 100
        || workspace_id.contains(['\0', '\r', '\n'])
        || (!workspace_id.is_empty() && provider != "claude")
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "workspace_id_invalid"));
    }
    provider::validate_preset(&provider, &base).map_err(|_| invalid())?;
    mutation_rate(app, "ai_check", 10).await?;
    let key = match v["api_key"].as_str().filter(|k| !k.is_empty()) {
        Some(k) => {
            if k.len() > 512 {
                return Err(invalid());
            }
            k.to_string()
        }
        None => {
            let row = sqlx::query("SELECT value,version FROM app_settings WHERE key='ai'")
                .fetch_one(&app.pool)
                .await?;
            let profile = row.get::<Value, _>("value");
            let id = uid(profile["id"].as_str().unwrap_or(""))?;
            match gateway::key_for(app, id, row.get::<i32, _>("version")).await {
                Ok(k) => k,
                Err(_) => {
                    return Ok(out(
                        json!({"ok":false,"code":"missing_key","provider":provider,"model":model,"latency_ms":0}),
                    ));
                }
            }
        }
    };
    let started = std::time::Instant::now();
    let workspace = (!workspace_id.is_empty()).then_some(workspace_id);
    let probed = provider::probe(&base, &key, workspace).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    let result = match probed {
        Ok(probe) => {
            let model_found = (!model.is_empty())
                .then(|| {
                    probe
                        .models
                        .as_ref()
                        .map(|ids| ids.iter().any(|id| id == model))
                })
                .flatten();
            let (ok, code) = match probe.status {
                200..=299 => (true, "ok"),
                401 | 403 => (false, "key_rejected"),
                429 => (false, "rate_limited"),
                _ => (false, "provider_error"),
            };
            json!({"ok":ok,"code":code,"status":probe.status,"provider":provider,"model":model,"latency_ms":latency_ms,"models":probe.models,"model_found":model_found})
        }
        Err(e) => {
            let code = if e.to_string().contains("destination_denied") {
                "destination_denied"
            } else {
                "unreachable"
            };
            json!({"ok":false,"code":code,"provider":provider,"model":model,"latency_ms":latency_ms})
        }
    };
    Ok(out(result))
}
pub fn encrypt(master: &str, value: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    let key = hex::decode(master)?;
    anyhow::ensure!(key.len() == 32, "master_key_invalid");
    let nonce = Uuid::new_v4().as_bytes()[..12].to_vec();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("encryption_error"))?
        .encrypt(Nonce::from_slice(&nonce), value.as_bytes())
        .map_err(|_| anyhow::anyhow!("encryption_error"))?;
    Ok((cipher, nonce))
}
async fn stream(app: &App, headers: &HeaderMap) -> Result<Response> {
    let watermark: i64 = sqlx::query_scalar("SELECT coalesce(max(id),0) FROM outbox_events")
        .fetch_one(&app.pool)
        .await?;
    let oldest: i64 = sqlx::query_scalar("SELECT coalesce(min(id),0) FROM outbox_events")
        .fetch_one(&app.pool)
        .await?;
    let start = if let Some(s) = headers.get("last-event-id") {
        s.to_str()
            .map_err(|_| invalid())?
            .parse::<i64>()
            .map_err(|_| invalid())?
    } else {
        watermark
    };
    if start < 0 {
        return Err(invalid());
    }
    let pool = app.pool.clone();
    let stream = async_stream::stream! {let mut last=start;
    yield Ok::<Event,Infallible>(Event::default().comment("connected"));
    if start>watermark||(start>0&&start<oldest){yield Ok::<Event,Infallible>(Event::default().event("resync_required").id(watermark.to_string()).data(json!({"watermark":watermark}).to_string()));return;}
    loop{let rows=sqlx::query("SELECT id,kind,payload FROM outbox_events WHERE id>$1 ORDER BY id LIMIT 1001").bind(last).fetch_all(&pool).await;
    match rows{Ok(rows)=>{if rows.len()>1000{let current:i64=sqlx::query_scalar("SELECT coalesce(max(id),0) FROM outbox_events").fetch_one(&pool).await.unwrap_or(last);yield Ok(Event::default().event("resync_required").id(current.to_string()).data(json!({"watermark":current}).to_string()));break;}for r in rows{last=r.get("id");yield Ok(Event::default().id(last.to_string()).event(r.get::<String,_>("kind")).retry(Duration::from_secs(3)).data(r.get::<Value,_>("payload").to_string()));}},Err(_)=>break,}
    tokio::time::sleep(Duration::from_millis(250)).await;
    }};
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}

fn validate_models(v: &Value, provider: &str) -> Result<()> {
    let models = v.as_object().ok_or_else(invalid)?;
    if models.len() > 2 {
        return Err(invalid());
    }
    for (name, spec) in models {
        if name.is_empty() || name.len() > 100 {
            return Err(invalid());
        }
        let spec: provider::ModelSpec =
            serde_json::from_value(spec.clone()).map_err(|_| invalid())?;
        spec.validate(provider).map_err(|_| invalid())?;
    }
    Ok(())
}
pub fn decrypt(master: &str, ciphertext: &[u8], nonce: &[u8]) -> anyhow::Result<String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    anyhow::ensure!(nonce.len() == 12, "credential_invalid");
    let key = hex::decode(master)?;
    let text = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("credential_invalid"))?
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("credential_invalid"))?;
    Ok(String::from_utf8(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_spend_limit_uses_exact_cents() {
        assert_eq!(usd_units("0.01").unwrap(), 1_000_000);
        assert_eq!(usd_units("1.2").unwrap(), 120_000_000);
        assert_eq!(usd_units("1000000.00").unwrap(), 100_000_000_000_000);
        for invalid_amount in ["0", "0.001", "-1", ".5", "1e3", "1000000.01"] {
            assert!(usd_units(invalid_amount).is_err());
        }
    }
    #[test]
    fn cursor_scope() {
        let q = HashMap::new();
        let c = cursor_encode(4, "/reports", &q);
        let q = HashMap::from([("cursor".into(), c)]);
        assert!(page(&q, "/events", &["cursor"]).is_err());
        assert_eq!(page(&q, "/reports", &["cursor"]).unwrap().1, Some(4));
    }
    #[test]
    fn crypto_roundtrip() {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        let master = "ab".repeat(32);
        let (v, n) = encrypt(&master, "canary").unwrap();
        assert!(!v.windows(6).any(|s| s == b"canary"));
        let c = Aes256Gcm::new_from_slice(&hex::decode(master).unwrap()).unwrap();
        assert_eq!(
            c.decrypt(Nonce::from_slice(&n), v.as_slice()).unwrap(),
            b"canary"
        );
    }
}
