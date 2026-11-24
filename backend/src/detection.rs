use crate::*;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
pub fn dispatch_time(
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    sent: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    let t = (last + Duration::seconds(5)).min(first + Duration::seconds(15));
    sent.map_or(t, |s| t.max(s + Duration::seconds(60)))
}
pub async fn drain(app: &App) -> anyhow::Result<()> {
    for _ in 0..200 {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(7616)")
            .execute(&mut *tx)
            .await?;
        let row=sqlx::query("SELECT e.* FROM detection_work w JOIN events e ON e.id=w.event_id WHERE w.state='pending' AND EXISTS(SELECT 1 FROM services v WHERE v.id=e.service_id AND v.enabled AND v.deleted_at IS NULL) ORDER BY w.ingest_seq LIMIT 1 FOR UPDATE OF w SKIP LOCKED").fetch_optional(&mut *tx).await?;
        let Some(e) = row else {
            break;
        };
        let event_id: Uuid = e.get("id");
        let run: Uuid = e.get("run_id");
        let event_type: String = e.get("event_type");
        let level: String = e.get("level");
        let time: DateTime<Utc> = e.get("ingested_at");
        let ip: Option<String> = e.get("src_ip");
        let user: Option<String> = e.get("user_alias");
        let service: Option<String> = e.get("service");
        let service_id: Option<Uuid> = e.get("service_id");
        let source: String = e.get("source");
        let message: String = e.get("message");
        let primary = if event_type == "auth.failed" {
            Some("R1")
        } else if event_type == "auth.success" {
            Some("R2")
        } else if event_type == "app.error" || event_type == "http.suspicious" {
            Some("R3")
        } else {
            None
        };
        let mut rules = Vec::new();
        if let Some(rule) = primary {
            rules.push(rule);
        }
        if message.to_lowercase().contains("ignora instrucciones")
            || message
                .to_lowercase()
                .contains("ignore previous instructions")
        {
            rules.push("R4");
        }
        let config = sqlx::query(
            "SELECT version,definition FROM business_rule_sets ORDER BY version DESC LIMIT 1",
        )
        .fetch_one(&mut *tx)
        .await?;
        let config_version: i32 = config.get("version");
        let definition: serde_json::Value = config.get("definition");
        let source_id: Uuid = e.get("source_id");
        let source_config = sqlx::query("SELECT coalesce(r.version,s.version) AS version,coalesce(r.analysis,s.analysis) AS analysis FROM sources s LEFT JOIN source_revisions r ON r.source_id=s.id AND r.version=$2 WHERE s.id=$1")
            .bind(source_id).bind(e.get::<Option<i32>,_>("source_version")).fetch_one(&mut *tx).await?;
        let source_version: i32 = source_config.get("version");
        let source_analysis: serde_json::Value = source_config.get("analysis");
        for rule in rules {
            let source_override = source_analysis["rules"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| r["id"] == rule);
            let condition = source_override.and_then(|r| r.get("condition"));
            if condition.is_some_and(|c| !services::condition_matches(c, &level, &source)) {
                continue;
            }
            let global_override = definition["rules"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| {
                    r["id"] == rule
                        && (r["service_id"]
                            .as_str()
                            .and_then(|id| id.parse::<Uuid>().ok())
                            == service_id
                            && service_id.is_some()
                            || r["service_id"].is_null() && r["service"].is_null())
                })
                .max_by_key(|r| !r["service_id"].is_null() || !r["service"].is_null());
            let overrides = source_override.or(global_override);
            if rule != "R4" && overrides.is_some_and(|r| r["enabled"] == false) {
                continue;
            }
            let usable = match rule {
                "R1" | "R2" => ip.is_some() && user.is_some() && service.is_some(),
                "R3" => service.is_some() && (event_type != "http.suspicious" || ip.is_some()),
                _ => true,
            };
            if usable {
                let mut group = match rule {
                    "R1" | "R2" => json!({"ip":ip,"user":user,"service_id":service_id}),
                    "R3" if event_type == "http.suspicious" => {
                        json!({"service_id":service_id,"ip":ip,"type":"http.suspicious"})
                    }
                    "R3" => json!({"service_id":service_id}),
                    _ => json!({"source":source,"service_id":service_id}),
                };
                if rule != "R4" {
                    group["business_version"] = json!(config_version);
                    if source_override.is_some() {
                        group["source_id"] = json!(source_id);
                        group["source_rule_version"] = json!(source_version);
                    }
                }
                let (mut window, mut threshold) = match rule {
                    "R1" => (60, 5),
                    "R2" => (120, 5),
                    "R3" => (30, 10),
                    _ => (0, 1),
                };
                if rule != "R4"
                    && let Some(r) = overrides
                {
                    window = r["window_seconds"].as_i64().unwrap();
                    threshold = r["threshold"].as_i64().unwrap() as usize;
                }
                let rule_version = if rule == "R4" { 1 } else { config_version };
                sqlx::query("INSERT INTO rule_versions VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                    .bind(rule)
                    .bind(rule_version)
                    .bind(&definition)
                    .bind(hash(definition.to_string()))
                    .execute(&mut *tx)
                    .await?;
                let existing=sqlx::query("SELECT * FROM incidents WHERE run_id=$1 AND rule_id=$2 AND (group_key=$3 OR (group_key - 'service' - 'service_id'=$3::jsonb - 'service' - 'service_id' AND EXISTS(SELECT 1 FROM incident_services z WHERE z.incident_id=incidents.id AND z.service_id=$5))) AND last_match_at >= $4 ORDER BY opened_at DESC LIMIT 1 FOR UPDATE").bind(run).bind(rule).bind(&group).bind(time-Duration::seconds(120)).bind(service_id).fetch_optional(&mut *tx).await?;
                let mut evidence: Vec<Uuid> = if rule == "R4"
                    || (existing.is_some() && matches!(rule, "R1" | "R3"))
                {
                    vec![event_id]
                } else {
                    sqlx::query_scalar("SELECT id FROM events WHERE run_id=$1 AND ingest_seq<=$2 AND ingested_at BETWEEN $3 AND $4 AND event_type=$5 AND ($6::text IS NULL OR src_ip=$6) AND ($7::text IS NULL OR user_alias=$7) AND service_id=$8 AND ($9::uuid IS NULL OR source_id=$9) AND ($10::text IS NULL OR ((CASE $10 WHEN 'level' THEN level WHEN 'source' THEN source END=$12) = ($11='eq'))) ORDER BY ingest_seq")
 .bind(run).bind(e.get::<i64,_>("ingest_seq")).bind(time-Duration::seconds(window)).bind(time).bind(if rule=="R3"{event_type.as_str()}else{"auth.failed"}).bind(if rule=="R3" && event_type!="http.suspicious"{None}else{ip.clone()}).bind(if rule=="R3"{None}else{user.clone()}).bind(service_id).bind(source_override.map(|_|source_id)).bind(condition.and_then(|c|c["field"].as_str())).bind(condition.and_then(|c|c["operator"].as_str())).bind(condition.and_then(|c|c["value"].as_str())).fetch_all(&mut *tx).await?
                };

                if evidence.len() >= threshold || (existing.is_some() && rule != "R2") {
                    if rule == "R2" {
                        evidence.push(event_id);
                    }
                    let (id, created, prev_version) = if let Some(ref r) = existing {
                        (
                            r.get::<Uuid, _>("id"),
                            false,
                            r.get::<i32, _>("evidence_version"),
                        )
                    } else {
                        (Uuid::new_v4(), true, 0)
                    };
                    let (severity, title) = match rule {
                        "R1" => ("high", "Fallos de autenticación concentrados"),
                        "R2" => ("critical", "Acceso exitoso tras fallos repetidos"),
                        "R3" if event_type == "http.suspicious" => {
                            ("medium", "Solicitudes repetidas a rutas sensibles")
                        }
                        "R3" => ("medium", "Errores de aplicación repetidos"),
                        _ => ("low", "Texto hostil en datos sintéticos"),
                    };
                    if created {
                        sqlx::query("INSERT INTO incidents(id,incident_key,run_id,rule_id,rule_version,group_key,severity,title,opened_at,last_match_at,deterministic_reason) VALUES($1,$2,$3,$4,$10,$5,$6,$7,$8,$8,$9)").bind(id).bind(hash(format!("{rule}:1:{run}:{group}:{event_id}"))).bind(run).bind(rule).bind(&group).bind(severity).bind(title).bind(time).bind(json!({"threshold":threshold,"window_seconds":window,"rule_version":rule_version,"trigger_event_id":event_id})).bind(rule_version).execute(&mut *tx).await?;
                    }
                    sqlx::query("INSERT INTO incident_services(incident_id,service_id) SELECT $1,$2 WHERE $2::uuid IS NOT NULL ON CONFLICT DO NOTHING").bind(id).bind(service_id).execute(&mut *tx).await?;
                    let mut added = 0;
                    for eid in evidence {
                        added+=sqlx::query("INSERT INTO incident_events(incident_id,event_id,role,added_version) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(id).bind(eid).bind(if eid==event_id{"trigger"}else{"match"}).bind(prev_version+1).execute(&mut *tx).await?.rows_affected();
                    }
                    if added > 0 {
                        let version = prev_version + 1;
                        let first = existing
                            .as_ref()
                            .and_then(|r| r.get::<Option<DateTime<Utc>>, _>("pending_since"))
                            .unwrap_or(time);
                        let sent = existing
                            .as_ref()
                            .and_then(|r| r.get::<Option<DateTime<Utc>>, _>("last_sent_at"));
                        sqlx::query("UPDATE incidents SET evidence_version=$2,report_version=report_version+1,last_match_at=$3,pending_since=$4,eligible_at=$5 WHERE id=$1").bind(id).bind(version).bind(time).bind(if rule=="R4"{None}else{Some(first)}).bind(if rule=="R4"{None}else{Some(dispatch_time(first,time,sent))}).execute(&mut *tx).await?;
                        db::emit(
                            &mut tx,
                            if created {
                                "report.created"
                            } else {
                                "report.updated"
                            },
                            id,
                            version,
                        )
                        .await?;
                    }
                    if rule == "R2" {
                        sqlx::query("INSERT INTO incident_relations(from_id,to_id,relation) SELECT $1,id,'following_failures' FROM incidents WHERE run_id=$2 AND rule_id='R1' AND (group_key=$3 OR (group_key - 'service' - 'service_id'=$3::jsonb - 'service' - 'service_id' AND EXISTS(SELECT 1 FROM incident_services z WHERE z.incident_id=incidents.id AND z.service_id=$4))) ON CONFLICT DO NOTHING").bind(id).bind(run).bind(&group).bind(service_id).execute(&mut *tx).await?;
                    }
                }
            } else {
                sqlx::query("UPDATE sources SET last_error_code='detection_missing_group_field' WHERE id=$1").bind(e.get::<Uuid,_>("source_id")).execute(&mut *tx).await?;
            }
        }
        observability_pass(&mut tx, &e).await?;
        custom_rules_pass(&mut tx, &e).await?;
        sqlx::query("UPDATE detection_work SET state='done',attempts=attempts+1 WHERE event_id=$1")
            .bind(event_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO detection_checkpoints(source_id,last_ingest_seq) VALUES($1,$2) ON CONFLICT(source_id) DO UPDATE SET last_ingest_seq=$2,updated_at=now()").bind(e.get::<Uuid,_>("source_id")).bind(e.get::<i64,_>("ingest_seq")).execute(&mut *tx).await?;
        if std::env::var("SENTINEL_FAILPOINT").as_deref() == Ok("detection_before_commit") {
            std::process::abort();
        }
        tx.commit().await?;
    }
    Ok(())
}

/// Reglas específicas del operador (id «custom:…»): contador genérico por
/// fuente. Cuenta los eventos de la MISMA fuente y corrida que coinciden
/// con la señal declarada dentro de la ventana; al llegar al umbral abre
/// (o extiende) una incidencia con el nombre y la severidad de la regla.
/// Es una señal determinista de revisión: no afirma acceso ni compromiso.
async fn custom_rules_pass(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &sqlx::postgres::PgRow,
) -> anyhow::Result<()> {
    let Some(service_id) = e.get::<Option<Uuid>, _>("service_id") else {
        return Ok(());
    };
    let event_id: Uuid = e.get("id");
    let event_type: String = e.get("event_type");
    let level: String = e.get("level");
    let source_id: Uuid = e.get("source_id");
    let source_analysis: Value = {
        let row = sqlx::query("SELECT coalesce(r.analysis,s.analysis) AS analysis FROM sources s LEFT JOIN source_revisions r ON r.source_id=s.id AND r.version=$2 WHERE s.id=$1")
            .bind(source_id).bind(e.get::<Option<i32>, _>("source_version")).fetch_one(&mut **tx).await?;
        row.get("analysis")
    };
    let run: Uuid = e.get("run_id");
    let time: DateTime<Utc> = e.get("ingested_at");
    let seq: i64 = e.get("ingest_seq");
    for rule in source_analysis["rules"].as_array().into_iter().flatten() {
        let Some(rule_id) = rule["id"].as_str().filter(|id| id.starts_with("custom:")) else {
            continue;
        };
        if rule["enabled"] == false {
            continue;
        }
        let signal = rule["signal"].as_str().unwrap_or("");
        if !services::custom_signal_matches(signal, &event_type, &level) {
            continue;
        }
        let threshold = rule["threshold"].as_i64().unwrap_or(1).max(1) as usize;
        let window = rule["window_seconds"].as_i64().unwrap_or(0).max(0);
        let severity = rule["severity"]
            .as_str()
            .filter(|s| ["low", "medium", "high", "critical"].contains(s))
            .unwrap_or("low");
        let name = rule["name"].as_str().unwrap_or(rule_id);
        let group =
            json!({"service_id": service_id, "source_id": source_id, "custom_rule": rule_id});
        let definition = json!({"kind": "custom", "version": 1, "signal": signal, "name": name});
        sqlx::query("INSERT INTO rule_versions VALUES($1,1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(rule_id)
            .bind(&definition)
            .bind(hash(definition.to_string()))
            .execute(&mut **tx)
            .await?;
        let existing = sqlx::query("SELECT * FROM incidents WHERE run_id=$1 AND rule_id=$2 AND group_key=$3 AND last_match_at >= $4 ORDER BY opened_at DESC LIMIT 1 FOR UPDATE")
            .bind(run).bind(rule_id).bind(&group).bind(time - Duration::seconds(300)).fetch_optional(&mut **tx).await?;
        let evidence: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM events WHERE run_id=$1 AND source_id=$2 AND ingest_seq<=$3 AND ingested_at BETWEEN $4 AND $5 AND (CASE $6 WHEN 'any' THEN true WHEN 'level.error' THEN level='error' ELSE event_type=$6 END) ORDER BY ingest_seq")
            .bind(run).bind(source_id).bind(seq).bind(time - Duration::seconds(window)).bind(time).bind(signal).fetch_all(&mut **tx).await?;
        if evidence.len() < threshold && existing.is_none() {
            continue;
        }
        let (id, created, prev_version) = if let Some(ref r) = existing {
            (
                r.get::<Uuid, _>("id"),
                false,
                r.get::<i32, _>("evidence_version"),
            )
        } else {
            (Uuid::new_v4(), true, 0)
        };
        if created {
            let reason = json!({"custom_rule": rule_id, "name": name, "signal": signal, "threshold": threshold, "window_seconds": window, "trigger_event_id": event_id, "note": "regla específica definida por el operador: señal determinista de revisión, no confirma acceso ni compromiso"});
            sqlx::query("INSERT INTO incidents(id,incident_key,run_id,rule_id,rule_version,group_key,severity,title,opened_at,last_match_at,deterministic_reason) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$8,$9)")
                .bind(id).bind(hash(format!("{rule_id}:1:{run}:{group}:{event_id}"))).bind(run).bind(rule_id).bind(&group).bind(severity).bind(name).bind(time).bind(reason).execute(&mut **tx).await?;
        }
        sqlx::query("INSERT INTO incident_services(incident_id,service_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(id).bind(service_id).execute(&mut **tx).await?;
        let mut added = 0;
        for eid in evidence {
            added += sqlx::query("INSERT INTO incident_events(incident_id,event_id,role,added_version) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(id).bind(eid).bind(if eid == event_id { "trigger" } else { "match" }).bind(prev_version + 1).execute(&mut **tx).await?.rows_affected();
        }
        if added > 0 {
            let version = prev_version + 1;
            let first = existing
                .as_ref()
                .and_then(|r| r.get::<Option<DateTime<Utc>>, _>("pending_since"))
                .unwrap_or(time);
            let sent = existing
                .as_ref()
                .and_then(|r| r.get::<Option<DateTime<Utc>>, _>("last_sent_at"));
            sqlx::query("UPDATE incidents SET evidence_version=$2,report_version=report_version+1,last_match_at=$3,pending_since=$4,eligible_at=$5 WHERE id=$1")
                .bind(id).bind(version).bind(time).bind(first).bind(dispatch_time(first, time, sent)).execute(&mut **tx).await?;
            db::emit(
                &mut *tx,
                if created {
                    "report.created"
                } else {
                    "report.updated"
                },
                id,
                version,
            )
            .await?;
        }
    }
    Ok(())
}

/// Clasificación determinista de observabilidad (OBS-01): persiste la
/// clasificación del evento contra el perfil activo de su servicio y crea
/// incidencias agrupadas para las plantillas de superficie habilitadas.
/// Nunca afirma acceso ni compromiso: es una señal de revisión.
async fn observability_pass(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &sqlx::postgres::PgRow,
) -> anyhow::Result<()> {
    let event_id: Uuid = e.get("id");
    let Some(service_id) = e.get::<Option<Uuid>, _>("service_id") else {
        return Ok(());
    };
    let http: Option<Value> = e.get("http");
    let entries = observability::active_entries(&mut **tx, service_id, Some("http")).await?;
    let http_entries: Vec<(Uuid, i32, Value)> = entries
        .iter()
        .map(|(id, rev, cfg, _)| (*id, *rev, cfg.clone()))
        .collect();
    let classification = observability::classify_http(http.as_ref(), &http_entries);
    let fp = observability::fingerprint(
        &entries
            .iter()
            .map(|(id, rev, _, h)| (*id, *rev, h.clone()))
            .collect::<Vec<_>>(),
    );
    sqlx::query("INSERT INTO event_classifications(event_id,service_id,classification,profile_fingerprint,matched_entry_id,matched_revision,reason) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(event_id) DO NOTHING")
        .bind(event_id).bind(service_id).bind(classification.kind).bind(&fp)
        .bind(classification.matched_entry_id).bind(classification.matched_revision)
        .bind(&classification.reason).execute(&mut **tx).await?;
    let template = match classification.kind {
        // method_not_allowed comparte la plantilla de superficie: la
        // declaración incluye los métodos y el grupo conserva la
        // clasificación exacta que lo originó.
        "outside_declared_boundary" | "method_not_allowed" => {
            Some("request_outside_declared_surface")
        }
        "encoded_traversal_attempt" => Some("encoded_path_traversal"),
        "ambiguous_normalization" => Some("ambiguous_request_normalization"),
        _ => None,
    };
    let Some(template) = template else {
        return Ok(());
    };
    let source_analysis: Value = {
        let row = sqlx::query("SELECT coalesce(r.analysis,s.analysis) AS analysis FROM sources s LEFT JOIN source_revisions r ON r.source_id=s.id AND r.version=$2 WHERE s.id=$1")
            .bind(e.get::<Uuid,_>("source_id")).bind(e.get::<Option<i32>,_>("source_version")).fetch_one(&mut **tx).await?;
        row.get("analysis")
    };
    let override_rule = source_analysis["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["id"] == template)
        .cloned();
    if override_rule
        .as_ref()
        .is_some_and(|r| r["enabled"] == false)
    {
        return Ok(());
    }
    let (_, _, default_threshold, default_window, default_severity) = observability::TEMPLATES
        .iter()
        .find(|(id, _, _, _, _)| *id == template)
        .copied()
        .unwrap();
    let threshold = override_rule
        .as_ref()
        .and_then(|r| r["threshold"].as_i64())
        .unwrap_or(default_threshold)
        .max(1) as usize;
    let window = override_rule
        .as_ref()
        .and_then(|r| r["window_seconds"].as_i64())
        .unwrap_or(default_window)
        .max(0);
    let severity = override_rule
        .as_ref()
        .and_then(|r| r["severity"].as_str())
        .filter(|s| ["low", "medium", "high", "critical"].contains(s))
        .unwrap_or(default_severity);
    let run: Uuid = e.get("run_id");
    let time: DateTime<Utc> = e.get("ingested_at");
    let path = classification.reason["observed_path"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let group = json!({"service_id":service_id,"classification":classification.kind,"path":path});
    let definition = json!({"template":template,"kind":"observability","version":1});
    sqlx::query("INSERT INTO rule_versions VALUES($1,1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(template)
        .bind(&definition)
        .bind(hash(definition.to_string()))
        .execute(&mut **tx)
        .await?;
    let existing = sqlx::query("SELECT * FROM incidents WHERE run_id=$1 AND rule_id=$2 AND group_key=$3 AND last_match_at >= $4 ORDER BY opened_at DESC LIMIT 1 FOR UPDATE")
        .bind(run).bind(template).bind(&group).bind(time - Duration::seconds(300)).fetch_optional(&mut **tx).await?;
    let evidence: Vec<Uuid> = sqlx::query_scalar("SELECT c.event_id FROM event_classifications c JOIN events ev ON ev.id=c.event_id WHERE ev.run_id=$1 AND ev.service_id=$2 AND c.classification=$3 AND c.reason->>'observed_path'=$4 AND ev.ingested_at BETWEEN $5 AND $6 AND ev.ingest_seq<=$7 ORDER BY ev.ingest_seq")
        .bind(run).bind(service_id).bind(classification.kind).bind(&path).bind(time - Duration::seconds(window)).bind(time).bind(e.get::<i64,_>("ingest_seq")).fetch_all(&mut **tx).await?;
    if evidence.len() < threshold && existing.is_none() {
        return Ok(());
    }
    let (id, created, prev_version) = if let Some(ref r) = existing {
        (
            r.get::<Uuid, _>("id"),
            false,
            r.get::<i32, _>("evidence_version"),
        )
    } else {
        (Uuid::new_v4(), true, 0)
    };
    if created {
        let title = match template {
            "encoded_path_traversal" => "Intento de path traversal observado",
            "ambiguous_request_normalization" => "Normalización de solicitud ambigua",
            _ => "Solicitud fuera de la superficie declarada",
        };
        let reason = json!({"template":template,"classification":classification.kind,"observed_path":path,"profile_fingerprint":fp,"matched_entry_id":classification.matched_entry_id,"threshold":threshold,"window_seconds":window,"trigger_event_id":event_id,"note":"señal determinista de revisión: no confirma acceso al recurso ni compromiso"});
        sqlx::query("INSERT INTO incidents(id,incident_key,run_id,rule_id,rule_version,group_key,severity,title,opened_at,last_match_at,deterministic_reason) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$8,$9)")
            .bind(id).bind(hash(format!("{template}:1:{run}:{group}:{event_id}"))).bind(run).bind(template).bind(&group).bind(severity).bind(title).bind(time).bind(reason).execute(&mut **tx).await?;
    }
    sqlx::query("INSERT INTO incident_services(incident_id,service_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(id).bind(service_id).execute(&mut **tx).await?;
    let mut added = 0;
    for eid in evidence {
        added += sqlx::query("INSERT INTO incident_events(incident_id,event_id,role,added_version) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(id).bind(eid).bind(if eid == event_id { "trigger" } else { "match" }).bind(prev_version + 1).execute(&mut **tx).await?.rows_affected();
    }
    if added > 0 {
        let version = prev_version + 1;
        let first = existing
            .as_ref()
            .and_then(|r| r.get::<Option<DateTime<Utc>>, _>("pending_since"))
            .unwrap_or(time);
        let sent = existing
            .as_ref()
            .and_then(|r| r.get::<Option<DateTime<Utc>>, _>("last_sent_at"));
        sqlx::query("UPDATE incidents SET evidence_version=$2,report_version=report_version+1,last_match_at=$3,pending_since=$4,eligible_at=$5 WHERE id=$1")
            .bind(id).bind(version).bind(time).bind(first).bind(dispatch_time(first, time, sent)).execute(&mut **tx).await?;
        db::emit(
            &mut *tx,
            if created {
                "report.created"
            } else {
                "report.updated"
            },
            id,
            version,
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scheduling() {
        let a = Utc::now();
        assert_eq!(dispatch_time(a, a, None), a + Duration::seconds(5));
        assert_eq!(
            dispatch_time(a, a + Duration::seconds(14), None),
            a + Duration::seconds(15)
        );
        assert_eq!(dispatch_time(a, a, Some(a)), a + Duration::seconds(60));
    }
}
