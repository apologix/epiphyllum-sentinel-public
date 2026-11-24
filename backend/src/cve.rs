use crate::{App, api::ApiError};
use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::Row;
use std::cmp::Ordering;
use uuid::Uuid;

type Result<T> = std::result::Result<T, ApiError>;
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
}

const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const MAX_FINDINGS: usize = 600;
const PAGE_SIZE: usize = 200;
const MAX_PAGES: usize = 3;

/// Valida un producto CPE "vendor:product" (minúsculas, [a-z0-9._-]).
pub fn validate_product(raw: &str) -> Result<(String, String)> {
    let lowered = raw.trim().to_lowercase();
    let mut parts = lowered.split(':');
    let (Some(vendor), Some(product), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    let (vendor, product) = (vendor.to_owned(), product.to_owned());
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 60
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    };
    if !ok(&vendor) || !ok(&product) {
        return Err(invalid());
    }
    Ok((vendor, product))
    // Nota: la validación de mayúsculas se hace sobre la copia en minúsculas;
    // los productos CPE válidos ya son minúsculas en el diccionario de NVD.
}

/// Lee el software declarado de un cuerpo de servicio: ambos campos o ninguno.
pub fn declared_software(v: &Value) -> Result<Option<(String, String)>> {
    let read = |key: &str| -> Result<Option<String>> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => {
                let s = value.as_str().ok_or_else(invalid)?.trim();
                Ok(if s.is_empty() {
                    None
                } else {
                    Some(s.to_owned())
                })
            }
        }
    };
    match (read("software_product")?, read("software_version")?) {
        (None, None) => Ok(None),
        (Some(product), Some(version)) => {
            validate_product(&product)?;
            if version.len() > 64 || version.contains(['\0', '\r', '\n', ' ']) {
                return Err(invalid());
            }
            Ok(Some((product.to_lowercase(), version)))
        }
        _ => Err(invalid()),
    }
}

fn version_segments(version: &str) -> Vec<(u64, String)> {
    version
        .split(['.', '-', '_', '+'])
        .map(|seg| {
            let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
            let num = digits.parse::<u64>().unwrap_or(0);
            (num, seg.to_lowercase())
        })
        .collect()
}

/// Comparación tolerante de versiones: segmentos numéricos primero, resto literal.
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let (sa, sb) = (version_segments(a), version_segments(b));
    for i in 0..sa.len().max(sb.len()) {
        let (na, ta) = sa.get(i).cloned().unwrap_or((0, String::new()));
        let (nb, tb) = sb.get(i).cloned().unwrap_or((0, String::new()));
        match na.cmp(&nb) {
            Ordering::Equal => {}
            other => return other,
        }
        match ta.cmp(&tb) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

struct MatchVerdict {
    affects: bool,
    range: String,
    fixed: Option<String>,
}

/// Evalúa un cpeMatch de NVD contra la versión declarada.
fn eval_match(m: &Value, declared: &str) -> Option<MatchVerdict> {
    if m["vulnerable"].as_bool() != Some(true) {
        return None;
    }
    let criteria = m["criteria"].as_str()?;
    let parts: Vec<&str> = criteria.split(':').collect();
    // cpe:2.3:a:vendor:product:version:...
    if parts.len() < 6 || parts[0] != "cpe" {
        return None;
    }
    let exact = parts[5];
    let start_inc = m["versionStartIncluding"].as_str();
    let start_exc = m["versionStartExcluding"].as_str();
    let end_inc = m["versionEndIncluding"].as_str();
    let end_exc = m["versionEndExcluding"].as_str();
    let has_bounds =
        start_inc.is_some() || start_exc.is_some() || end_inc.is_some() || end_exc.is_some();
    let affects = if exact != "*" && exact != "-" && !has_bounds {
        cmp_version(declared, exact) == Ordering::Equal
    } else {
        let mut ok = true;
        if let Some(v) = start_inc {
            ok &= cmp_version(declared, v) != Ordering::Less;
        }
        if let Some(v) = start_exc {
            ok &= cmp_version(declared, v) == Ordering::Greater;
        }
        if let Some(v) = end_inc {
            ok &= cmp_version(declared, v) != Ordering::Greater;
        }
        if let Some(v) = end_exc {
            ok &= cmp_version(declared, v) == Ordering::Less;
        }
        ok
    };
    let range = if has_bounds {
        let lo = start_inc
            .map(|v| format!("desde {v}"))
            .or_else(|| start_exc.map(|v| format!("después de {v}")))
            .unwrap_or_else(|| "desde el inicio".to_owned());
        let hi = end_exc
            .map(|v| format!("hasta antes de {v}"))
            .or_else(|| end_inc.map(|v| format!("hasta {v}")))
            .unwrap_or_else(|| "sin cota superior".to_owned());
        format!("{lo}, {hi}")
    } else if exact != "*" {
        format!("versión exacta {exact}")
    } else {
        "todas las versiones".to_owned()
    };
    Some(MatchVerdict {
        affects,
        range,
        fixed: end_exc.map(str::to_owned),
    })
}

pub struct Finding {
    pub cve_id: String,
    pub severity: String,
    pub base_score: Option<f64>,
    pub summary: String,
    pub published: Option<String>,
    pub affects: bool,
    pub affected_range: Option<String>,
    pub fixed_version: Option<String>,
    pub refs: Vec<String>,
}

fn severity_of(cve: &Value) -> (String, Option<f64>) {
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(m) = cve["metrics"][key].as_array().and_then(|a| a.first()) {
            let data = &m["cvssData"];
            if let Some(score) = data["baseScore"].as_f64() {
                let severity = data["baseSeverity"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_lowercase();
                return (severity, Some(score));
            }
        }
    }
    ("unknown".to_owned(), None)
}

/// Convierte la respuesta de NVD en hallazgos con veredicto determinista.
pub fn parse_findings(body: &Value, product: &str, declared: &str) -> Vec<Finding> {
    let (vendor, name) = match validate_product(product) {
        Ok(pair) => pair,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for item in body["vulnerabilities"].as_array().into_iter().flatten() {
        let cve = &item["cve"];
        let Some(cve_id) = cve["id"].as_str() else {
            continue;
        };
        let mut verdict: Option<MatchVerdict> = None;
        for cfg in cve["configurations"].as_array().into_iter().flatten() {
            for node in cfg["nodes"].as_array().into_iter().flatten() {
                for m in node["cpeMatch"].as_array().into_iter().flatten() {
                    let Some(criteria) = m["criteria"].as_str() else {
                        continue;
                    };
                    let parts: Vec<&str> = criteria.split(':').collect();
                    if parts.len() < 6
                        || parts[3] != vendor
                        || parts[4] != name
                        || m["vulnerable"].as_bool() != Some(true)
                    {
                        continue;
                    }
                    if let Some(v) = eval_match(m, declared) {
                        let better = match &verdict {
                            None => true,
                            Some(prev) => v.affects && !prev.affects,
                        };
                        if better {
                            verdict = Some(v);
                        }
                    }
                }
            }
        }
        let Some(verdict) = verdict else {
            continue;
        };
        let (severity, base_score) = severity_of(cve);
        let summary = cve["descriptions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|d| d["lang"] == "en")
            .and_then(|d| d["value"].as_str())
            .unwrap_or("")
            .chars()
            .take(2000)
            .collect();
        let refs: Vec<String> = cve["references"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["url"].as_str().map(str::to_owned))
            .take(5)
            .collect();
        out.push(Finding {
            cve_id: cve_id.to_owned(),
            severity,
            base_score,
            summary,
            published: cve["published"].as_str().map(str::to_owned),
            affects: verdict.affects,
            affected_range: Some(verdict.range),
            fixed_version: if verdict.affects { verdict.fixed } else { None },
            refs,
        });
        if out.len() >= MAX_FINDINGS {
            break;
        }
    }
    out.sort_by(|a, b| {
        b.affects
            .cmp(&a.affects)
            .then(b.published.cmp(&a.published))
    });
    out
}

struct CheckRecord<'a> {
    service_id: Uuid,
    product: &'a str,
    version: &'a str,
    state: &'a str,
    total: i32,
    findings: &'a [Finding],
    error: Option<&'a str>,
}

async fn record_check(app: &App, rec: CheckRecord<'_>) -> Result<Value> {
    let (service_id, product, version, state, total, findings, error) = (
        rec.service_id,
        rec.product,
        rec.version,
        rec.state,
        rec.total,
        rec.findings,
        rec.error,
    );
    let check_id = Uuid::new_v4();
    let affecting = findings.iter().filter(|f| f.affects).count() as i32;
    let mut tx = app.pool.begin().await?;
    sqlx::query("INSERT INTO cve_checks(id,service_id,product,version,state,total_reported,affecting_count,error) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(check_id)
        .bind(service_id)
        .bind(product)
        .bind(version)
        .bind(state)
        .bind(total)
        .bind(affecting)
        .bind(error)
        .execute(&mut *tx)
        .await?;
    for f in findings {
        sqlx::query("INSERT INTO cve_findings(id,check_id,service_id,cve_id,severity,base_score,summary,published,affects,affected_range,fixed_version,refs) VALUES($1,$2,$3,$4,$5,$6,$7,$8::timestamptz,$9,$10,$11,$12) ON CONFLICT DO NOTHING")
            .bind(Uuid::new_v4())
            .bind(check_id)
            .bind(service_id)
            .bind(&f.cve_id)
            .bind(&f.severity)
            .bind(f.base_score)
            .bind(&f.summary)
            .bind(&f.published)
            .bind(f.affects)
            .bind(&f.affected_range)
            .bind(&f.fixed_version)
            .bind(json!(f.refs))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    latest(app, service_id).await
}

/// Ejecuta una comprobación contra NVD para el software actual del servicio.
/// Lee (producto, versión) al inicio y el registro guarda exactamente eso:
/// si el servicio cambia de versión mientras la consulta está en vuelo, el
/// resultado se guarda como historial de la versión consultada y nunca se
/// presenta como vigente de la nueva (la vigencia se decide por coincidencia
/// en `latest`, `services_summary` y `findings_page`).
pub async fn run_check(app: &App, service_id: Uuid) -> Result<Value> {
    let row = sqlx::query(
        "SELECT software_product,software_version,deleted_at FROM services WHERE id=$1",
    )
    .bind(service_id)
    .fetch_optional(&app.pool)
    .await?
    .ok_or_else(invalid)?;
    if row
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("deleted_at")
        .is_some()
    {
        return Err(invalid());
    }
    let product: Option<String> = row.get("software_product");
    let version: Option<String> = row.get("software_version");
    let (Some(product), Some(version)) = (product, version) else {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "software_not_declared",
        ));
    };
    let (vendor, name) = validate_product(&product)?;
    let cpe = format!("cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*");
    let mut merged: Vec<Value> = Vec::new();
    let mut total: i64 = 0;
    let mut fetch_error: Option<reqwest::Error> = None;
    for page in 0..MAX_PAGES {
        let url = format!(
            "{}?virtualMatchString={}&resultsPerPage={}&startIndex={}",
            NVD_URL,
            urlencoding(&cpe),
            PAGE_SIZE,
            page * PAGE_SIZE
        );
        let response = app
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .header("User-Agent", "EpiphyllumSentinel/0.1 (CVE check)")
            .send()
            .await;
        match response {
            Ok(r) if r.status().is_success() => match r.json::<Value>().await {
                Ok(body) => {
                    total = body["totalResults"].as_i64().unwrap_or(0);
                    if let Some(items) = body["vulnerabilities"].as_array() {
                        merged.extend(items.iter().cloned());
                    }
                    if (merged.len() as i64) >= total || merged.is_empty() {
                        break;
                    }
                }
                Err(e) => {
                    fetch_error = Some(e);
                    break;
                }
            },
            Ok(r) => {
                fetch_error = r.error_for_status().err();
                break;
            }
            Err(e) => {
                fetch_error = Some(e);
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    }
    match fetch_error {
        None => {
            let body = json!({"totalResults": total, "vulnerabilities": merged});
            let findings = parse_findings(&body, &product, &version);
            record_check(
                app,
                CheckRecord {
                    service_id,
                    product: &product,
                    version: &version,
                    state: "completed",
                    total: total as i32,
                    findings: &findings,
                    error: None,
                },
            )
            .await
        }
        Some(e) => {
            let message = format!("No se pudo consultar NVD: {e}");
            let _ = record_check(
                app,
                CheckRecord {
                    service_id,
                    product: &product,
                    version: &version,
                    state: "failed",
                    total: 0,
                    findings: &[],
                    error: Some(&message),
                },
            )
            .await;
            Err(ApiError(StatusCode::BAD_GATEWAY, "cve_source_unavailable"))
        }
    }
}

fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Última comprobación VIGENTE del servicio con sus hallazgos (CVE-07,
/// sección 3): un chequeo solo es vigente si su (producto, versión) coincide
/// con el software actual del servicio — `cve_checks` ya guarda ambos por
/// chequeo (migración 0024), no hace falta migración. Si el último chequeo
/// fue para otra versión (el servicio cambió de A a B), queda en el
/// historial y se expone como `previous_check`, pero `check` es null y los
/// hallazgos de A no se devuelven: B está «pendiente de comprobar».
pub async fn latest(app: &App, service_id: Uuid) -> Result<Value> {
    let software: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT software_product,software_version FROM services WHERE id=$1")
            .bind(service_id)
            .fetch_optional(&app.pool)
            .await?;
    let (current_product, current_version) = software.unwrap_or((None, None));
    let check: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(c) FROM cve_checks c WHERE service_id=$1 ORDER BY checked_at DESC,id DESC LIMIT 1",
    )
    .bind(service_id)
    .fetch_optional(&app.pool)
    .await?;
    let Some(check) = check else {
        return Ok(json!({"check": null, "previous_check": null, "findings": [], "history": []}));
    };
    if !check_is_current(&check, &current_product, &current_version) {
        let history: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(h) FROM (SELECT id,state,total_reported,affecting_count,error,product,version,checked_at FROM cve_checks WHERE service_id=$1 ORDER BY checked_at DESC,id DESC LIMIT 10) h",
        )
        .bind(service_id)
        .fetch_all(&app.pool)
        .await?;
        return Ok(
            json!({"check": null, "previous_check": check, "findings": [], "history": history}),
        );
    }
    let findings: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(f) FROM cve_findings f WHERE check_id=$1 ORDER BY affects DESC, published DESC NULLS LAST",
    )
    .bind(check["id"].as_str().and_then(|s| s.parse::<Uuid>().ok()))
    .fetch_all(&app.pool)
    .await?;
    let history: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(h) FROM (SELECT id,state,total_reported,affecting_count,error,product,version,checked_at FROM cve_checks WHERE service_id=$1 ORDER BY checked_at DESC,id DESC LIMIT 10) h",
    )
    .bind(service_id)
    .fetch_all(&app.pool)
    .await?;
    Ok(json!({"check": check, "previous_check": null, "findings": findings, "history": history}))
}

/// Un chequeo es vigente solo si consultó exactamente el (producto, versión)
/// que el servicio tiene ahora. Función pura para poder probarla sin base.
pub fn check_is_current(
    check: &Value,
    current_product: &Option<String>,
    current_version: &Option<String>,
) -> bool {
    match (current_product, current_version) {
        (Some(p), Some(v)) => {
            check["product"].as_str() == Some(p.as_str())
                && check["version"].as_str() == Some(v.as_str())
        }
        _ => false,
    }
}

/// ¿Está activo el chequeo diario? (app_settings clave 'cve'; ACTIVADO por
/// defecto desde la decisión de automatización total de 2026-11-21: el
/// interruptor de Ajustes es un opt-out, no un opt-in.)
pub async fn daily_enabled(app: &App) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT coalesce((value->>'enabled')::boolean,true) FROM app_settings WHERE key='cve'",
    )
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(true)
}

pub async fn settings(app: &App) -> Result<Value> {
    let row = sqlx::query("SELECT value,version FROM app_settings WHERE key='cve'")
        .fetch_optional(&app.pool)
        .await?;
    match row {
        Some(r) => Ok(json!({
            "enabled": r.get::<Value, _>("value")["enabled"].as_bool().unwrap_or(false),
            "version": r.get::<i32, _>("version"),
        })),
        None => Ok(json!({"enabled": true, "version": 0})),
    }
}

pub async fn save_settings(app: &App, v: &Value) -> Result<Value> {
    let enabled = v["enabled"].as_bool().ok_or_else(invalid)?;
    let expected = v["expected_version"]
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .ok_or_else(invalid)?;
    let current = settings(app).await?;
    if current["version"].as_i64() != Some(i64::from(expected)) {
        return Err(ApiError(StatusCode::CONFLICT, "conflict"));
    }
    sqlx::query("INSERT INTO app_settings(key,value,version) VALUES('cve',$1,1) ON CONFLICT(key) DO UPDATE SET value=$1,version=app_settings.version+1,updated_at=now()")
        .bind(json!({"enabled": enabled}))
        .execute(&app.pool)
        .await?;
    settings(app).await
}

/// Ciclo diario automático (CVE-07): comprueba los servicios activos sin
/// comprobación en 24 h que tengan versión CONFIRMADA: declarada por el
/// operador ('operator') o publicada por el propio servicio vía MCP
/// ('mcp'). Los banners ya no se adoptan: son solo sugerencias para el
/// operador, y una procedencia histórica 'banner' no cuenta como versión
/// confirmada, así que esos servicios no se comprueban hasta que el
/// operador declare el software o el servicio lo publique vía MCP.
/// Sin versión confirmada no se crea registro en `cve_checks`: su modelo
/// exige producto y versión no nulos y estados completed/failed, así que
/// no hay forma honesta de registrar un «omitido» sin inventar datos.
pub async fn due_checks(app: &App) {
    if !daily_enabled(app).await {
        return;
    }
    // La ventana de 24 h solo la bloquea un chequeo de la versión ACTUAL:
    // si el servicio cambió de A a B, el chequeo reciente de A queda en el
    // historial pero no debe impedir el primer chequeo de B.
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT s.id FROM services s WHERE s.deleted_at IS NULL AND s.enabled AND s.software_product IS NOT NULL AND s.software_version IS NOT NULL AND (s.software_origin IS NULL OR s.software_origin IN ('operator','mcp')) AND NOT EXISTS(SELECT 1 FROM cve_checks c WHERE c.service_id=s.id AND c.product=s.software_product AND c.version=s.software_version AND c.checked_at>now()-interval '24 hours')",
    )
    .fetch_all(&app.pool)
    .await
    .unwrap_or_default();
    for id in ids {
        let _ = run_check(app, id).await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison_handles_common_shapes() {
        assert_eq!(cmp_version("2.4.58", "2.4.60"), Ordering::Less);
        assert_eq!(cmp_version("2.4.60", "2.4.60"), Ordering::Equal);
        assert_eq!(cmp_version("9.3", "9.3p2"), Ordering::Less);
        assert_eq!(cmp_version("1.1.1w", "1.1.1u"), Ordering::Greater);
        assert_eq!(cmp_version("8.0", "8.0.1"), Ordering::Less);
    }

    #[test]
    fn parses_nvd_ranges_and_marks_affecting() {
        let body = json!({
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-38474",
                    "published": "2024-07-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "SSRF in Apache HTTP Server."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [{
                        "vulnerable": true,
                        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "2.4.0",
                        "versionEndExcluding": "2.4.60"
                    }]}]}],
                    "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}]
                }
            }]
        });
        let findings = parse_findings(&body, "apache:http_server", "2.4.58");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].affects);
        assert_eq!(findings[0].fixed_version.as_deref(), Some("2.4.60"));
        assert_eq!(findings[0].severity, "critical");
        let safe = parse_findings(&body, "apache:http_server", "2.4.62");
        assert!(!safe[0].affects);
        assert!(safe[0].fixed_version.is_none());
    }

    #[test]
    fn product_validation_is_closed() {
        assert!(validate_product("apache:http_server").is_ok());
        assert!(validate_product("sin-dos-puntos").is_err());
        assert!(validate_product("Apache:HTTP Server").is_err());
        assert!(validate_product("a:b:c").is_err());
    }
}

// ---------- Tab CVE: resumen, tabla global, banner y explicaciones ----------

/// Hallazgos de la última comprobación completada de cada servicio, para
/// incluirlos como contexto en el análisis y el chat de sus incidencias
/// (CVE-02c): primero los que afectan, máximo 10, resumen truncado.
pub async fn findings_for_services(app: &App, service_ids: &[Uuid]) -> Vec<Value> {
    if service_ids.is_empty() {
        return Vec::new();
    }
    sqlx::query_scalar(
        "SELECT jsonb_build_object('service_id',f.service_id,'cve_id',f.cve_id,'severity',f.severity,'base_score',f.base_score,'affects',f.affects,'fixed_version',f.fixed_version,'summary',left(f.summary,280),'product',c.product,'installed_version',c.version,'checked_at',c.checked_at) FROM cve_findings f JOIN cve_checks c ON c.id=f.check_id WHERE f.service_id=ANY($1) AND c.state='completed' AND c.id=(SELECT x.id FROM cve_checks x JOIN services sv ON sv.id=x.service_id WHERE x.service_id=f.service_id AND x.state='completed' AND x.product=sv.software_product AND x.version=sv.software_version ORDER BY x.checked_at DESC,x.id DESC LIMIT 1) ORDER BY f.affects DESC, f.base_score DESC NULLS LAST LIMIT 10",
    )
    .bind(service_ids)
    .fetch_all(&app.pool)
    .await
    .unwrap_or_default()
}

/// Resumen por servicio para la pestaña CVE: chequeo VIGENTE y conteos.
/// `check` es el último chequeo cuyo (producto, versión) coincide con el
/// software actual del servicio; si el último chequeo fue para otra
/// versión, va en `previous_check` (producto, versión y fecha consultados)
/// y el servicio se presenta «pendiente de comprobar» la versión actual.
pub async fn services_summary(app: &App) -> Result<Value> {
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',s.id,'name',s.name,'enabled',s.enabled,'software_product',s.software_product,'software_version',s.software_version,'software_origin',s.software_origin,'check',(SELECT to_jsonb(c) FROM cve_checks c WHERE c.service_id=s.id AND c.product=s.software_product AND c.version=s.software_version ORDER BY c.checked_at DESC,c.id DESC LIMIT 1),'previous_check',(SELECT jsonb_build_object('product',c.product,'version',c.version,'state',c.state,'checked_at',c.checked_at) FROM cve_checks c WHERE c.service_id=s.id AND NOT (c.product=s.software_product AND c.version=s.software_version) ORDER BY c.checked_at DESC,c.id DESC LIMIT 1)) FROM services s WHERE s.deleted_at IS NULL ORDER BY lower(s.name)",
    )
    .fetch_all(&app.pool)
    .await?;
    Ok(json!({"items": rows, "daily_enabled": daily_enabled(app).await}))
}

/// Hallazgos de la última comprobación completa de cada servicio, paginados en servidor.
pub async fn findings_page(
    app: &App,
    query: &std::collections::HashMap<String, String>,
) -> Result<Value> {
    let service_id = query
        .get("service_id")
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| invalid())?;
    let severity = query.get("severity").map(|s| s.as_str());
    if let Some(s) = severity
        && !["critical", "high", "medium", "low", "none", "unknown"].contains(&s)
    {
        return Err(invalid());
    }
    let affects = match query.get("affects").map(|s| s.as_str()) {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return Err(invalid()),
    };
    let text = query.get("q").filter(|s| !s.trim().is_empty());
    let limit: i64 = query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .filter(|n| (1..=100).contains(n))
        .unwrap_or(25);
    let offset: i64 = query
        .get("offset")
        .and_then(|s| s.parse().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(0);
    // Solo hallazgos del chequeo vigente: el último completado cuyo
    // (producto, versión) coincide con el software actual del servicio.
    // Los de versiones anteriores quedan en el historial, fuera de la
    // tabla vigente, la cobertura y el donut.
    let filter = "c.id=(SELECT x.id FROM cve_checks x JOIN services sv ON sv.id=x.service_id WHERE x.service_id=f.service_id AND x.state='completed' AND x.product=sv.software_product AND x.version=sv.software_version ORDER BY x.checked_at DESC,x.id DESC LIMIT 1) AND ($1::uuid IS NULL OR f.service_id=$1) AND ($2::text IS NULL OR f.severity=$2) AND ($3::bool IS NULL OR f.affects=$3) AND ($4::text IS NULL OR f.cve_id ILIKE '%'||$4||'%' OR f.summary ILIKE '%'||$4||'%')";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM cve_findings f JOIN cve_checks c ON c.id=f.check_id WHERE {filter}"
    ))
    .bind(service_id)
    .bind(severity)
    .bind(affects)
    .bind(text)
    .fetch_one(&app.pool)
    .await?;
    let items: Vec<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(f)||jsonb_build_object('service_name',s.name,'product',c.product,'version',c.version,'checked_at',c.checked_at) FROM cve_findings f JOIN cve_checks c ON c.id=f.check_id JOIN services s ON s.id=f.service_id WHERE {filter} ORDER BY f.affects DESC, CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, f.base_score DESC NULLS LAST, f.published DESC NULLS LAST LIMIT $5 OFFSET $6"
    ))
    .bind(service_id)
    .bind(severity)
    .bind(affects)
    .bind(text)
    .bind(limit)
    .bind(offset)
    .fetch_all(&app.pool)
    .await?;
    Ok(json!({"items": items, "total_count": total, "limit": limit, "offset": offset}))
}

/// Comprobación manual de todos los servicios con versión confirmada
/// (declarada por el operador o vía MCP; una adopción histórica 'banner'
/// no cuenta como confirmada, igual que en el ciclo diario).
pub async fn run_all(app: &App) -> Result<Value> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM services WHERE deleted_at IS NULL AND software_product IS NOT NULL AND software_version IS NOT NULL AND (software_origin IS NULL OR software_origin IN ('operator','mcp')) ORDER BY lower(name)",
    )
    .fetch_all(&app.pool)
    .await?;
    let mut results = Vec::new();
    for id in ids {
        match run_check(app, id).await {
            Ok(data) => results.push(json!({
                "service_id": id,
                "state": "completed",
                "affecting_count": data["check"]["affecting_count"],
                "total_reported": data["check"]["total_reported"],
            })),
            Err(_) => results.push(json!({"service_id": id, "state": "failed"})),
        }
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    }
    Ok(json!({"results": results}))
}

const BANNER_PATTERNS: [(&str, &str); 6] = [
    ("Apache/", "apache:http_server"),
    ("nginx/", "nginx:nginx"),
    ("OpenSSH_", "openbsd:openssh"),
    ("PHP/", "php:php"),
    ("PostgreSQL ", "postgresql:postgresql"),
    ("Microsoft-IIS/", "microsoft:internet_information_services"),
];

/// Detecta versiones desde banners presentes en textos ya ingeridos.
pub fn detect_banners(texts: &[String]) -> Vec<Value> {
    let mut counts: std::collections::HashMap<(String, String), i64> =
        std::collections::HashMap::new();
    for text in texts {
        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for (prefix, product) in BANNER_PATTERNS {
            let mut rest = text.as_str();
            while let Some(pos) = rest.find(prefix) {
                let tail = &rest[pos + prefix.len()..];
                let version: String = tail
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || ".-_+".contains(*c))
                    .collect();
                let version = version.trim_end_matches(['.', '-', '_']).to_owned();
                if version.chars().next().is_some_and(|c| c.is_ascii_digit()) && version.len() <= 32
                {
                    seen.insert((product.to_owned(), version));
                }
                rest = &rest[pos + prefix.len()..];
            }
        }
        for key in seen {
            *counts.entry(key).or_default() += 1;
        }
    }
    let mut out: Vec<Value> = counts
        .into_iter()
        .map(|((product, version), records)| json!({"product": product, "version": version, "records": records}))
        .collect();
    out.sort_by(|a, b| b["records"].as_i64().cmp(&a["records"].as_i64()));
    out.truncate(5);
    out
}

/// Sugerencias de software desde los banners de la evidencia del servicio.
pub async fn banner_suggestions(app: &App, service_id: Uuid) -> Result<Value> {
    let texts: Vec<String> = sqlx::query_scalar(
        "SELECT safe_text FROM text_records WHERE service_id=$1 ORDER BY received_at DESC LIMIT 1000",
    )
    .bind(service_id)
    .fetch_all(&app.pool)
    .await?;
    Ok(json!({"suggestions": detect_banners(&texts), "records_scanned": texts.len()}))
}

pub async fn create_explanation(app: &App, finding_id: Uuid, v: &Value) -> Result<Value> {
    let question = v
        .get("question")
        .and_then(|q| q.as_str())
        .map(|q| q.trim().to_owned())
        .filter(|q| !q.is_empty())
        .unwrap_or_else(|| {
            "¿Cómo me afecta esta vulnerabilidad y cómo la puedo solucionar?".to_owned()
        });
    if question.chars().count() > 1000 || question.contains('\0') {
        return Err(invalid());
    }
    let service_id: Uuid = sqlx::query_scalar("SELECT service_id FROM cve_findings WHERE id=$1")
        .bind(finding_id)
        .fetch_optional(&app.pool)
        .await?
        .ok_or_else(invalid)?;
    let row: Value = sqlx::query_scalar(
        "INSERT INTO cve_explanations(id,finding_id,service_id,question) VALUES($1,$2,$3,$4) RETURNING to_jsonb(cve_explanations)",
    )
    .bind(Uuid::new_v4())
    .bind(finding_id)
    .bind(service_id)
    .bind(&question)
    .fetch_one(&app.pool)
    .await?;
    Ok(row)
}

pub async fn list_explanations(app: &App, finding_id: Uuid) -> Result<Value> {
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM cve_explanations e WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 20",
    )
    .bind(finding_id)
    .fetch_all(&app.pool)
    .await?;
    Ok(json!({"items": rows}))
}

fn mock_explanation(finding: &Value, service: &Value) -> (String, Vec<String>) {
    let affects = finding["affects"].as_bool() == Some(true);
    let fix = match finding["fixed_version"].as_str() {
        Some(v) => format!("Actualizá a la versión {v} o superior siguiendo el aviso del proveedor; después verificá el banner del servicio y repetí la comprobación para confirmar que el CVE ya no figura como afectante."),
        None => "NVD no publica una versión corregida única para este caso: seguí las mitigaciones y actualizaciones del aviso del proveedor enlazado en las referencias.".to_owned(),
    };
    let answer = format!(
        "Generación mock (sin gasto): explicación local construida con los datos oficiales de NVD; no es la respuesta de un modelo en vivo.\n\nQué es: {}\n\nTu exposición: el servicio {} corre {} {}. Según los rangos publicados por NVD ({}), tu versión {} dentro del rango vulnerable.\n\nCómo solucionarlo: {}",
        finding["summary"]
            .as_str()
            .unwrap_or("Sin descripción disponible."),
        service["name"].as_str().unwrap_or(""),
        finding["product"].as_str().unwrap_or(""),
        finding["version"].as_str().unwrap_or(""),
        finding["affected_range"]
            .as_str()
            .unwrap_or("sin rango publicado"),
        if affects { "está" } else { "no está" },
        fix
    );
    let checks = vec![
        "Confirmá la versión real instalada antes de actualizar; la declaración puede estar desactualizada.".to_owned(),
        "Aplicá el cambio en una ventana acordada y verificá el banner tras reiniciar el servicio.".to_owned(),
        "Repetí «Comprobar ahora» y confirmá que el CVE ya no aparece como afectante.".to_owned(),
    ];
    (answer, checks)
}

struct ExplanationOutcome<'a> {
    state: &'a str,
    answer: Option<&'a str>,
    checks: &'a [String],
    origin: Option<&'a str>,
    model: Option<&'a str>,
    reason: Option<&'a str>,
}

async fn finish_explanation(app: &App, id: Uuid, outcome: ExplanationOutcome<'_>) {
    let (state, answer, checks, origin, model, reason) = (
        outcome.state,
        outcome.answer,
        outcome.checks,
        outcome.origin,
        outcome.model,
        outcome.reason,
    );
    let _ = sqlx::query("UPDATE cve_explanations SET state=$2,answer=$3,human_checks=$4,origin=$5,model=$6,reason=$7,finished_at=now() WHERE id=$1")
        .bind(id)
        .bind(state)
        .bind(answer)
        .bind(json!(checks))
        .bind(origin)
        .bind(model)
        .bind(reason)
        .execute(&app.pool)
        .await;
}

/// Worker de explicaciones: procesa de a una, con el perfil mock sin gasto o
/// con live solo bajo la autorización de sesión vigente y su presupuesto.
pub async fn process_explanations(app: &App) {
    let claimed: Option<(Uuid, Uuid, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "UPDATE cve_explanations SET state='generating' WHERE id=(SELECT id FROM cve_explanations WHERE state='pending' ORDER BY created_at LIMIT 1) RETURNING id, finding_id, question, created_at",
    )
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten();
    let Some((id, finding_id, question, _created_at)) = claimed else {
        return;
    };
    let finding: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(f)||jsonb_build_object('product',c.product,'version',c.version) FROM cve_findings f JOIN cve_checks c ON c.id=f.check_id WHERE f.id=$1",
    )
    .bind(finding_id)
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten();
    let Some(finding) = finding else {
        finish_explanation(
            app,
            id,
            ExplanationOutcome {
                state: "failed",
                answer: None,
                checks: &[],
                origin: None,
                model: None,
                reason: Some("El hallazgo ya no existe."),
            },
        )
        .await;
        return;
    };
    let service: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('name',name,'context',coalesce((SELECT r.context FROM service_revisions r WHERE r.service_id=services.id AND r.version=services.version),''),'software_product',software_product,'software_version',software_version) FROM services WHERE id=$1",
    )
    .bind(finding["service_id"].as_str().and_then(|s| s.parse::<Uuid>().ok()))
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| json!({}));
    let profile_row = sqlx::query("SELECT value,version FROM app_settings WHERE key='ai'")
        .fetch_optional(&app.pool)
        .await
        .ok()
        .flatten();
    let Some(profile_row) = profile_row else {
        finish_explanation(
            app,
            id,
            ExplanationOutcome {
                state: "blocked",
                answer: None,
                checks: &[],
                origin: None,
                model: None,
                reason: Some("No hay un perfil de IA configurado."),
            },
        )
        .await;
        return;
    };
    let profile: Value = profile_row.get("value");
    let profile_version: i32 = profile_row.get("version");
    let provider_name = profile["provider"].as_str().unwrap_or("mock").to_owned();
    if provider_name == "mock" {
        let (answer, checks) = mock_explanation(&finding, &service);
        finish_explanation(
            app,
            id,
            ExplanationOutcome {
                state: "ready",
                answer: Some(&answer),
                checks: &checks,
                origin: Some("mock"),
                model: Some("mock-v1"),
                reason: None,
            },
        )
        .await;
        return;
    }
    // Live: ruta chat, costo peor caso y autorización de sesión vigente.
    let route = crate::gateway::route(&profile, profile_version, "chat", "R1", false);
    let model = route["model"].as_str().unwrap_or("").to_owned();
    let spec_value = &route["spec"];
    let parse_time = |v: &Value| {
        v.as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now)
    };
    let spec = crate::provider::ModelSpec {
        format: spec_value["format"]
            .as_str()
            .unwrap_or("json_object")
            .to_owned(),
        output_cap: spec_value["output_cap"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
        input_cap: spec_value["input_cap"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
        timeout_seconds: spec_value["timeout_seconds"].as_u64().unwrap_or(30),
        input_rate_units: spec_value["input_rate_units"].as_u64().unwrap_or(0),
        output_rate_units: spec_value["output_rate_units"].as_u64().unwrap_or(0),
        verified_at: parse_time(&spec_value["verified_at"]),
        source_url: spec_value["source_url"].as_str().unwrap_or("").to_owned(),
        token_bound_method: spec_value["token_bound_method"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        billable_output_bounded: spec_value["billable_output_bounded"]
            .as_bool()
            .unwrap_or(false),
        free_account_verified: spec_value["free_account_verified"]
            .as_bool()
            .unwrap_or(false),
    };
    if spec.output_cap == 0
        || spec.input_cap == 0
        || spec.input_rate_units == 0
        || spec.output_rate_units == 0
    {
        finish_explanation(app, id, ExplanationOutcome { state: "blocked", answer: None, checks: &[], origin: None, model: Some(&model), reason: Some("Las capacidades y la tarifa del modelo no están verificadas; la explicación no se envió.") }).await;
        return;
    }
    let snapshot = json!({
        "provider": provider_name,
        "kind": "cve_explanation",
        "question": question,
        "cve": {
            "id": finding["cve_id"], "severity": finding["severity"], "base_score": finding["base_score"],
            "summary": finding["summary"], "affects": finding["affects"], "affected_range": finding["affected_range"],
            "fixed_version": finding["fixed_version"], "refs": finding["refs"],
            "product": finding["product"], "installed_version": finding["version"]
        },
        "service": service,
        "events": [], "chunks": [], "policies": []
    });
    let input_upper = (snapshot.to_string().len() + 2048) as u64;
    let worst = crate::gateway::worst_case_units(
        input_upper,
        u64::from(spec.output_cap),
        spec.input_rate_units,
        spec.output_rate_units,
    )
    .unwrap_or(i64::MAX);
    // Autorización: la pregunta es una acción explícita del operador sobre un
    // hallazgo concreto, con el costo peor caso acotado por el spec verificado.
    // Si el tope monetario de sesión está activo, el peor caso debe caber en
    // el saldo restante de la cuenta de sesión. (El mecanismo anterior,
    // gateway::Authorization, no tiene constructor en producción y bloqueaba
    // siempre; la contabilidad fina en el ledger sigue en CVE-02b.)
    let cap: Option<(bool, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT cap_enabled,limit_units,spent_units,cap_baseline_spent_units,reserved_units FROM budget_accounts WHERE scope='session' AND scope_key=$1",
    )
    .bind(&app.config.session_id)
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten();
    let permitted = match cap {
        Some((true, limit, spent, baseline, reserved)) => {
            worst <= limit - (spent - baseline) - reserved
        }
        _ => true,
    };
    if !permitted {
        finish_explanation(app, id, ExplanationOutcome { state: "blocked", answer: None, checks: &[], origin: None, model: Some(&model), reason: Some("El costo peor caso de la explicación supera el saldo del tope monetario de sesión activo; la explicación no se envió. Ajustá el tope en Ajustes o usá el perfil mock.") }).await;
        return;
    }
    let key = match app.volatile_key.lock().await.clone() {
        Some(k) => Some(k),
        None => {
            let profile_id = profile["id"].as_str().and_then(|s| s.parse::<Uuid>().ok());
            match profile_id {
                Some(pid) => crate::gateway::key_for(app, pid, profile_version)
                    .await
                    .ok(),
                None => None,
            }
        }
    };
    let Some(key) = key else {
        finish_explanation(app, id, ExplanationOutcome { state: "blocked", answer: None, checks: &[], origin: None, model: Some(&model), reason: Some("No hay una credencial disponible para el proveedor; la explicación no se envió.") })
        .await;
        return;
    };
    let base = route["base_url"].as_str().unwrap_or("").to_owned();
    match crate::provider::generate(
        &base,
        &key,
        &model,
        "chat",
        &snapshot,
        &spec,
        route["workspace_id"].as_str().filter(|s| !s.is_empty()),
    )
    .await
    {
        Ok(generation) => {
            if let Some(error) = generation.error {
                finish_explanation(
                    app,
                    id,
                    ExplanationOutcome {
                        state: "failed",
                        answer: None,
                        checks: &[],
                        origin: Some("live"),
                        model: Some(&model),
                        reason: Some(error),
                    },
                )
                .await;
                return;
            }
            let content = generation.content.unwrap_or(Value::Null);
            let answer = content["answer"].as_str().map(str::to_owned);
            let checks: Vec<String> = content["human_checks"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect();
            match answer {
                Some(answer) if !answer.trim().is_empty() => {
                    finish_explanation(
                        app,
                        id,
                        ExplanationOutcome {
                            state: "ready",
                            answer: Some(&answer),
                            checks: &checks,
                            origin: Some("live"),
                            model: Some(&model),
                            reason: None,
                        },
                    )
                    .await;
                }
                _ => {
                    finish_explanation(
                        app,
                        id,
                        ExplanationOutcome {
                            state: "failed",
                            answer: None,
                            checks: &[],
                            origin: Some("live"),
                            model: Some(&model),
                            reason: Some("invalid_model_response"),
                        },
                    )
                    .await
                }
            }
        }
        Err(_) => {
            finish_explanation(
                app,
                id,
                ExplanationOutcome {
                    state: "failed",
                    answer: None,
                    checks: &[],
                    origin: Some("live"),
                    model: Some(&model),
                    reason: Some("provider_unavailable"),
                },
            )
            .await
        }
    }
}

#[cfg(test)]
mod banner_tests {
    use super::*;

    #[test]
    fn detects_versions_from_banners() {
        let texts = vec![
            "Server: Apache/2.4.58 (Unix) OpenSSL/3.0.0".to_owned(),
            "SSH-2.0-OpenSSH_9.3p2 Debian".to_owned(),
            "GET / HTTP/1.1\r\nServer: nginx/1.24.0".to_owned(),
            "sin banner acá".to_owned(),
            "otro Apache/2.4.58 de nuevo".to_owned(),
        ];
        let found = detect_banners(&texts);
        let apache = found
            .iter()
            .find(|f| f["product"] == "apache:http_server")
            .unwrap();
        assert_eq!(apache["version"], "2.4.58");
        assert_eq!(apache["records"], 2);
        assert!(
            found
                .iter()
                .any(|f| f["product"] == "openbsd:openssh" && f["version"] == "9.3p2")
        );
        assert!(
            found
                .iter()
                .any(|f| f["product"] == "nginx:nginx" && f["version"] == "1.24.0")
        );
    }

    #[test]
    fn ignores_versionless_mentions() {
        let texts = vec!["Apache es un servidor web".to_owned(), "nginx".to_owned()];
        assert!(detect_banners(&texts).is_empty());
    }
}

#[cfg(test)]
mod currency_tests {
    use super::*;

    #[test]
    fn a_check_is_current_only_for_the_same_product_and_version() {
        let check = json!({"product": "nginx:nginx", "version": "1.27.5"});
        let current = (Some("nginx:nginx".to_owned()), Some("1.27.5".to_owned()));
        assert!(check_is_current(&check, &current.0, &current.1));
        // Cambio de versión A -> B: el chequeo de A deja de ser vigente.
        let after_update = (Some("nginx:nginx".to_owned()), Some("1.28.0".to_owned()));
        assert!(!check_is_current(&check, &after_update.0, &after_update.1));
        // Cambio de producto (nginx:nginx -> f5:nginx): tampoco es vigente.
        let other_product = (Some("f5:nginx".to_owned()), Some("1.27.5".to_owned()));
        assert!(!check_is_current(
            &check,
            &other_product.0,
            &other_product.1
        ));
        // Sin versión confirmada no hay chequeo vigente posible.
        assert!(!check_is_current(&check, &None, &None));
        assert!(!check_is_current(
            &check,
            &Some("nginx:nginx".to_owned()),
            &None
        ));
    }
}
