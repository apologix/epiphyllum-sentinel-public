use crate::{App, api::ApiError, hash};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

type Result<T> = std::result::Result<T, ApiError>;
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
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
fn uuid_value(v: &Value, key: &str) -> Result<Uuid> {
    v[key]
        .as_str()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())
}
const PROFILES: [&str; 4] = [
    "event_correlation",
    "exposure_inventory",
    "config_audit",
    "known_vulns",
];
pub fn profiles() -> Value {
    json!({"items":[
        {"id":"event_correlation","name":"Correlación con eventos","version":1,"available":true,"description":"Relaciona las incidencias vinculadas al servicio con sus registros ya ingeridos en el periodo elegido.","limits":"Solo lectura de datos de Sentinel. Sin red, sin escaneo activo y sin gasto de IA."},
        {"id":"exposure_inventory","name":"Inventario de exposición desde evidencia","version":1,"available":true,"description":"Resume la superficie observada en la evidencia: fuentes del servicio con su sistema y protocolo, e IPs origen observadas en los eventos.","limits":"No es un escaneo de puertos. Solo resume evidencia ya ingerida por Sentinel."},
        {"id":"config_audit","name":"Auditoría local de configuración","version":1,"available":false,"description":"Comprobaciones de hardening del sistema instalado en la VM de laboratorio, con privilegio mínimo y lectura solamente.","limits":"Requiere un adaptador de herramienta fijado por versión y un análisis de impacto separado."},
        {"id":"known_vulns","name":"Revisión de vulnerabilidades conocidas","version":1,"available":true,"description":"Lee las comprobaciones CVE guardadas del software declarado del servicio (fuente NVD) y resume cuáles afectan a la versión declarada.","limits":"No consulta la red: usa la última comprobación guardada del detector CVE. El veredicto compara la versión declarada con los rangos que publica NVD."}
    ]})
}
fn profile_available(profile: &str) -> bool {
    matches!(profile, "event_correlation" | "exposure_inventory")
}
fn filter_hash(q: &HashMap<String, String>, scope: &str) -> String {
    let mut filters = q
        .iter()
        .filter(|(k, _)| k.as_str() != "cursor")
        .collect::<Vec<_>>();
    filters.sort();
    hash(format!("{scope}:{filters:?}"))
}
type Cursor = (i64, Option<(DateTime<Utc>, Uuid)>);

fn cursor(q: &HashMap<String, String>) -> Result<Cursor> {
    if q.keys()
        .any(|k| !["service_id", "profile", "state", "cursor", "limit"].contains(&k.as_str()))
    {
        return Err(invalid());
    }
    let limit = q
        .get("limit")
        .map(|s| s.parse::<i64>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(25);
    if !(1..=100).contains(&limit)
        || q.get("profile")
            .is_some_and(|s| !PROFILES.contains(&s.as_str()))
        || q.get("state")
            .is_some_and(|s| !["running", "completed", "blocked", "failed"].contains(&s.as_str()))
    {
        return Err(invalid());
    }
    if let Some(raw) = q.get("service_id") {
        raw.parse::<Uuid>().map_err(|_| invalid())?;
    }
    let at = q
        .get("cursor")
        .map(|c| {
            let v: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(c).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
            if v["filters"] != filter_hash(q, "lab-analyses") {
                return Err(invalid());
            }
            let at: DateTime<Utc> = v["name"]
                .as_str()
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?;
            Ok((at, uuid_value(&v, "id")?))
        })
        .transpose()?;
    Ok((limit, at))
}
pub async fn list(app: &App, q: &HashMap<String, String>) -> Result<Value> {
    let (limit, at) = cursor(q)?;
    let service_id = q
        .get("service_id")
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| invalid())?;
    let filter = "($1::uuid IS NULL OR a.service_id=$1) AND ($2::text IS NULL OR a.profile=$2) AND ($3::text IS NULL OR a.state=$3)";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM lab_analyses a WHERE {filter}"
    ))
    .bind(service_id)
    .bind(q.get("profile"))
    .bind(q.get("state"))
    .fetch_one(&app.pool)
    .await?;
    let mut rows: Vec<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(a)||jsonb_build_object('service_name',s.name) FROM lab_analyses a JOIN services s ON s.id=a.service_id WHERE {filter} AND ($4::timestamptz IS NULL OR (a.created_at,a.id)<($4,$5)) ORDER BY a.created_at DESC,a.id DESC LIMIT $6"
    ))
    .bind(service_id)
    .bind(q.get("profile"))
    .bind(q.get("state"))
    .bind(at.as_ref().map(|x| x.0))
    .bind(at.as_ref().map(|x| x.1))
    .bind(limit + 1)
    .fetch_all(&app.pool)
    .await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().map(|r| {
            URL_SAFE_NO_PAD.encode(
                json!({"name":r["created_at"],"id":r["id"],"filters":filter_hash(q,"lab-analyses")})
                    .to_string(),
            )
        })
    } else {
        None
    };
    Ok(json!({"items":rows,"total_count":total,"next_cursor":next}))
}
pub async fn detail(app: &App, id: Uuid) -> Result<Value> {
    let row: Value = sqlx::query_scalar(
        "SELECT to_jsonb(a)||jsonb_build_object('service_name',s.name) FROM lab_analyses a JOIN services s ON s.id=a.service_id WHERE a.id=$1",
    )
    .bind(id)
    .fetch_one(&app.pool)
    .await?;
    Ok(row)
}
pub async fn create(app: &App, body: &Value) -> Result<Value> {
    fields(
        body,
        &[
            "service_id",
            "profile",
            "period_days",
            "objective",
            "confirmed",
        ],
    )?;
    if body["confirmed"].as_bool() != Some(true) {
        return Err(invalid());
    }
    let service_id = uuid_value(body, "service_id")?;
    let profile = text(body, "profile", 40, 40)?;
    if !PROFILES.contains(&profile.as_str()) {
        return Err(invalid());
    }
    let period_days = body["period_days"].as_i64().ok_or_else(invalid)?;
    if ![7_i64, 30, 90].contains(&period_days) {
        return Err(invalid());
    }
    let objective = match body.get("objective") {
        None => String::new(),
        Some(_) => text(body, "objective", 500, 2000)?,
    };
    let service = sqlx::query("SELECT name FROM services WHERE id=$1 AND deleted_at IS NULL")
        .bind(service_id)
        .fetch_one(&app.pool)
        .await?;
    let service_name: String = service.get("name");
    let id = Uuid::new_v4();
    let scope = json!({"target":"service","service_id":service_id,"service_name":service_name,"period_days":period_days,"confirmed":true,"activity":if profile_available(&profile) {"read_only_ingested_data"} else {"none"}});
    sqlx::query("INSERT INTO lab_analyses(id,service_id,profile,profile_version,objective,scope,state) VALUES($1,$2,$3,1,$4,$5,'running')")
        .bind(id)
        .bind(service_id)
        .bind(&profile)
        .bind(&objective)
        .bind(&scope)
        .execute(&app.pool)
        .await?;
    if !profile_available(&profile) {
        let limitations = json!([
            "Este perfil requiere un adaptador de herramienta de laboratorio fijado por versión y un análisis de impacto separado; no se ejecutó ninguna herramienta.",
            "El blueprint prohíbe habilitar perfiles activos sin fijar ejecutable, parámetros cerrados, límites y pruebas."
        ]);
        sqlx::query(
            "UPDATE lab_analyses SET state='blocked',limitations=$2,finished_at=now() WHERE id=$1",
        )
        .bind(id)
        .bind(&limitations)
        .execute(&app.pool)
        .await?;
        return detail(app, id).await;
    }
    let outcome = run_profile(app, &profile, service_id, &service_name, period_days as i32).await;
    match outcome {
        Ok((summary, findings, stats, limitations)) => {
            sqlx::query("UPDATE lab_analyses SET state='completed',summary=$2,findings=$3,stats=$4,limitations=$5,finished_at=now() WHERE id=$1")
                .bind(id)
                .bind(&summary)
                .bind(&findings)
                .bind(&stats)
                .bind(&limitations)
                .execute(&app.pool)
                .await?;
        }
        Err(_) => {
            let limitations = json!([
                "El análisis no pudo completarse; no se reportan resultados parciales ni éxito."
            ]);
            let _ = sqlx::query("UPDATE lab_analyses SET state='failed',limitations=$2,finished_at=now() WHERE id=$1")
                .bind(id)
                .bind(&limitations)
                .execute(&app.pool)
                .await;
        }
    }
    detail(app, id).await
}
async fn run_profile(
    app: &App,
    profile: &str,
    service_id: Uuid,
    service_name: &str,
    days: i32,
) -> std::result::Result<(String, Value, Value, Value), sqlx::Error> {
    match profile {
        "event_correlation" => {
            let grouped: Value = sqlx::query_scalar(
                "SELECT coalesce(jsonb_agg(x),'[]') FROM (SELECT i.rule_id,i.severity,count(*)::bigint AS n,max(i.opened_at) AS last_opened FROM incidents i JOIN incident_services ss ON ss.incident_id=i.id WHERE ss.service_id=$1 AND i.opened_at>now()-make_interval(days=>$2) GROUP BY i.rule_id,i.severity ORDER BY i.rule_id,i.severity) x",
            )
            .bind(service_id)
            .bind(days)
            .fetch_one(&app.pool)
            .await?;
            let records: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM text_records WHERE service_id=$1 AND received_at>now()-make_interval(days=>$2)",
            )
            .bind(service_id)
            .bind(days)
            .fetch_one(&app.pool)
            .await?;
            let rank = |s: &str| match s {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                _ => 1,
            };
            let mut per_rule: Vec<(String, i64, String)> = Vec::new();
            let mut total: i64 = 0;
            if let Some(rows) = grouped.as_array() {
                for row in rows {
                    let rule = row["rule_id"].as_str().unwrap_or("").to_owned();
                    let severity = row["severity"].as_str().unwrap_or("low").to_owned();
                    let n = row["n"].as_i64().unwrap_or(0);
                    total += n;
                    if let Some(entry) = per_rule.iter_mut().find(|(r, _, _)| *r == rule) {
                        entry.1 += n;
                        if rank(&severity) > rank(&entry.2) {
                            entry.2 = severity;
                        }
                    } else {
                        per_rule.push((rule, n, severity));
                    }
                }
            }
            let findings: Vec<Value> = if per_rule.is_empty() {
                vec![
                    json!({"kind":"observation","severity":"low","title":"Sin incidencias vinculadas en el periodo","detail":"No se observaron incidencias de este servicio en la ventana elegida. Esto no confirma ausencia de actividad, solo de detecciones registradas."}),
                ]
            } else {
                per_rule
                    .iter()
                    .map(|(rule, n, severity)| {
                        json!({"kind":"observation","severity":severity,"title":format!("{n} incidencia(s) de la regla {rule} en el periodo"),"detail":format!("Severidad máxima registrada para esta regla: {severity}. Correlación determinista sobre incidencias ya vinculadas al servicio.")})
                    })
                    .collect()
            };
            let summary = format!(
                "Se correlacionaron {total} incidencia(s) vinculadas y {records} registro(s) del servicio en los últimos {days} días."
            );
            let stats =
                json!({"incidents_total":total,"records_total":records,"by_rule_severity":grouped});
            let limitations = json!([
                "Correlación determinista sobre datos ya ingeridos; no incluye actividad que las fuentes no hayan registrado.",
                "Las incidencias se atribuyen al servicio por su vínculo en el catálogo; los registros sin servicio asociado no se atribuyen."
            ]);
            Ok((summary, json!(findings), stats, limitations))
        }
        "known_vulns" => {
            let data = crate::cve::latest(app, service_id)
                .await
                .map_err(|_| sqlx::Error::RowNotFound)?;
            let check = &data["check"];
            if check.is_null() {
                let findings = vec![
                    json!({"kind":"observation","severity":"low","title":"Todavía no hay comprobaciones CVE para este servicio","detail":"Declarà el software y su versión en Editar servicio y ejecutá «Comprobar ahora», o activá el chequeo diario en Ajustes."}),
                ];
                let limitations = json!([
                    "Este perfil no consulta la red: lee las comprobaciones guardadas por el detector CVE (fuente NVD)."
                ]);
                return Ok((
                    "Sin comprobaciones CVE registradas para este servicio.".to_owned(),
                    json!(findings),
                    json!({"checks":0}),
                    limitations,
                ));
            }
            let findings_in = data["findings"].as_array().cloned().unwrap_or_default();
            let affecting: Vec<&Value> = findings_in
                .iter()
                .filter(|f| f["affects"].as_bool() == Some(true))
                .collect();
            let mut findings: Vec<Value> = affecting
                .iter()
                .map(|f| {
                    let fix = f["fixed_version"].as_str().map(|v| format!(" Versión corregida según NVD: actualizá a {v} o superior siguiendo el aviso del proveedor.")).unwrap_or_default();
                    json!({"kind":"vulnerability","severity":f["severity"].as_str().unwrap_or("low"),"title":format!("{} afecta a {} {}", f["cve_id"].as_str().unwrap_or("CVE"), check["product"].as_str().unwrap_or(""), check["version"].as_str().unwrap_or("")),"detail":format!("{}{}", f["summary"].as_str().unwrap_or(""), fix)})
                })
                .collect();
            if findings.is_empty() {
                findings.push(json!({"kind":"observation","severity":"low","title":"Ningún CVE conocido afecta a la versión declarada","detail":"Según los rangos vulnerables publicados por NVD en la última comprobación. Esto no garantiza ausencia de vulnerabilidades no publicadas."}));
            }
            let summary = format!(
                "Última comprobación CVE del {}: {} CVE revisado(s) para {} {}, {} afecta(n) a la versión declarada.",
                check["checked_at"].as_str().unwrap_or(""),
                check["total_reported"].as_i64().unwrap_or(0),
                check["product"].as_str().unwrap_or(""),
                check["version"].as_str().unwrap_or(""),
                affecting.len()
            );
            let stats = json!({"total_reported":check["total_reported"],"affecting":affecting.len(),"checked_at":check["checked_at"],"product":check["product"],"version":check["version"]});
            let limitations = json!([
                "Fuente: NVD (NIST), consulta por CPE del software declarado por el operador; Sentinel no detecta versiones desde los registros.",
                "El veredicto compara la versión declarada con los rangos de configurations de NVD; la remediación es informativa y la ejecuta una persona."
            ]);
            Ok((summary, json!(findings), stats, limitations))
        }
        _ => {
            let sources: Value = sqlx::query_scalar(
                "SELECT coalesce(jsonb_agg(x),'[]') FROM (SELECT kind,analysis->>'system' AS system,analysis->>'protocol' AS protocol,enabled FROM sources WHERE service_id=$1 AND deleted_at IS NULL ORDER BY kind,system) x",
            )
            .bind(service_id)
            .fetch_one(&app.pool)
            .await?;
            let ips: Value = sqlx::query_scalar(
                "SELECT coalesce(jsonb_agg(x),'[]') FROM (SELECT src_ip,count(*)::bigint AS n FROM events WHERE service=$1 AND src_ip IS NOT NULL AND event_time>now()-make_interval(days=>$2) GROUP BY src_ip ORDER BY n DESC LIMIT 20) x",
            )
            .bind(service_name)
            .bind(days)
            .fetch_one(&app.pool)
            .await?;
            let types: Value = sqlx::query_scalar(
                "SELECT coalesce(jsonb_agg(DISTINCT event_type),'[]') FROM events WHERE service=$1 AND event_time>now()-make_interval(days=>$2)",
            )
            .bind(service_name)
            .bind(days)
            .fetch_one(&app.pool)
            .await?;
            let mut findings: Vec<Value> = Vec::new();
            if let Some(rows) = sources.as_array() {
                if rows.is_empty() {
                    findings.push(json!({"kind":"observation","severity":"low","title":"El servicio no tiene fuentes registradas","detail":"Sin fuentes no hay evidencia que resumir; registrá una fuente en Servicios."}));
                }
                for row in rows {
                    findings.push(json!({"kind":"surface","severity":"low","title":format!("Fuente {}: {} / {}",row["kind"].as_str().unwrap_or(""),row["system"].as_str().unwrap_or("Sin especificar"),row["protocol"].as_str().unwrap_or("Sin especificar")),"detail":if row["enabled"].as_bool()==Some(true) {"Fuente activa en el catálogo."} else {"Fuente inactiva en el catálogo."}}));
                }
            }
            let mut distinct_ips = 0;
            if let Some(rows) = ips.as_array() {
                distinct_ips = rows.len();
                for row in rows.iter().take(5) {
                    findings.push(json!({"kind":"observation","severity":"low","title":format!("IP origen observada {}",row["src_ip"].as_str().unwrap_or("")),"detail":format!("Aparece en {} evento(s) del periodo. Es un origen observado en registros, no un activo verificado.",row["n"].as_i64().unwrap_or(0))}));
                }
            }
            let source_count = sources.as_array().map(|a| a.len()).unwrap_or(0);
            let summary = format!(
                "Superficie observada desde la evidencia: {source_count} fuente(s) registrada(s) y {distinct_ips} IP(s) origen distinta(s) en los últimos {days} días."
            );
            let stats = json!({"sources":sources,"top_src_ips":ips,"event_types":types,"distinct_src_ips":distinct_ips});
            let limitations = json!([
                "Inventario construido solo desde evidencia ya ingerida; no se realizó escaneo activo de puertos ni descubrimiento de red.",
                "Las IPs listadas son orígenes observados en registros, no activos verificados del laboratorio."
            ]);
            Ok((summary, json!(findings), stats, limitations))
        }
    }
}
