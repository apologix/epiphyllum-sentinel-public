use crate::*;
use chrono::Utc;
use contracts::*;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
/// Operator maintenance switch: saving a provider cannot bypass an explicit pause.
pub fn generation_paused() -> bool {
    std::env::var("GENERATION_PAUSED").as_deref() == Ok("1")
}
pub async fn settle(
    app: &App,
    attempt: Uuid,
    state: &str,
    response: Option<Value>,
    usage: Option<(i32, i32)>,
) -> anyhow::Result<()> {
    let mut tx = app.pool.begin().await?;
    let a=sqlx::query("SELECT a.*,j.incident_id,j.kind,j.message_id,j.snapshot,j.route,j.provider,j.evidence_version FROM analysis_attempts a JOIN analysis_jobs j ON j.id=a.job_id WHERE a.id=$1 FOR UPDATE OF a").bind(attempt).fetch_one(&mut *tx).await?;
    if !["reserved", "in_flight"].contains(&a.get::<String, _>("state").as_str()) {
        return Ok(());
    }
    let reserved: i64 = a.get("reserved_units");
    let live = a.get::<String, _>("provider") != "mock";
    let route: Value = a.get("route");
    let spec = serde_json::from_value::<provider::ModelSpec>(route["spec"].clone()).ok();
    let tariff_unknown =
        a.get::<Option<String>, _>("error_code").as_deref() == Some("model_mismatch");
    let charge = if state == "unknown" || (live && tariff_unknown) {
        reserved
    } else if live {
        match (usage, spec.as_ref()) {
            (Some((input, output)), Some(spec)) => worst_case_units(
                input as u64,
                output as u64,
                spec.input_rate_units,
                spec.output_rate_units,
            )?,
            _ => reserved,
        }
    } else {
        0
    };
    if charge > reserved {
        *app.authorization.lock().await = None;
    }
    let reservations=sqlx::query("SELECT * FROM budget_reservations WHERE attempt_id=$1 AND state='reserved' ORDER BY account_scope,account_key FOR UPDATE").bind(attempt).fetch_all(&mut *tx).await?;
    for r in reservations {
        sqlx::query("UPDATE budget_accounts SET reserved_units=reserved_units-$3,spent_units=spent_units+$4 WHERE scope=$1 AND scope_key=$2").bind(r.get::<String,_>("account_scope")).bind(r.get::<String,_>("account_key")).bind(r.get::<i64,_>("amount_units")).bind(charge).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE budget_reservations SET state='settled' WHERE attempt_id=$1")
        .bind(attempt)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE analysis_attempts SET state=$2,finished_at=now(),accounted_units=$3,input_tokens=$4,output_tokens=$5,usage_estimated=$6 WHERE id=$1").bind(attempt).bind(state).bind(charge).bind(usage.map(|u|u.0)).bind(usage.map(|u|u.1)).bind(usage.is_none() || tariff_unknown || a.get::<String,_>("provider") == "deepseek").execute(&mut *tx).await?;
    let job: Uuid = a.get("job_id");
    let incident: Option<Uuid> = a.get("incident_id");
    sqlx::query("UPDATE analysis_jobs SET state=$2,reason=CASE WHEN $2='unknown' THEN 'ambiguous_request_no_retry' WHEN $2='failed' AND EXISTS(SELECT 1 FROM analysis_attempts WHERE job_id=$1 AND error_code='partial_coverage') THEN 'partial_coverage_missing_ids' WHEN $2='failed' THEN 'invalid_provider_response' ELSE NULL END WHERE id=$1").bind(job).bind(state).execute(&mut *tx).await?;
    if let Some(value) = response {
        if a.get::<String, _>("kind") == "review" {
            crate::review::apply(&mut tx, job, &value, if live { "live" } else { "mock" }).await?;
        }
        sqlx::query("INSERT INTO analyses(id,job_id,origin,response) VALUES($1,$2,$4,$3)")
            .bind(Uuid::new_v4())
            .bind(job)
            .bind(&value)
            .bind(if live { "live" } else { "mock" })
            .execute(&mut *tx)
            .await?;
        if a.get::<String, _>("kind") == "chat"
            && let Some(mid) = a.get::<Option<Uuid>, _>("message_id")
        {
            insert_assistant(&mut tx, mid, &value, a.get("evidence_version"), state).await?;
        }
    }
    if let Some(mid) = a.get::<Option<Uuid>, _>("message_id") {
        sqlx::query("UPDATE messages SET state=$2 WHERE id=$1")
            .bind(mid)
            .bind(state)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE incidents SET report_version=report_version+1 WHERE id=$1")
        .bind(incident)
        .execute(&mut *tx)
        .await?;
    db::emit(
        &mut tx,
        if a.get::<String, _>("kind") == "review" {
            "coverage.updated"
        } else if a.get::<String, _>("kind") == "chat" {
            "conversation.updated"
        } else {
            "report.updated"
        },
        incident.unwrap_or(job),
        a.get("evidence_version"),
    )
    .await?;
    db::emit(&mut tx, "budget.updated", incident.unwrap_or(job), 1).await?;
    tx.commit().await?;
    Ok(())
}
async fn insert_assistant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mid: Uuid,
    value: &Value,
    ev: i32,
    state: &str,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO messages(id,conversation_id,ordinal,role,content,state,evidence_version,request_id,payload_hash,reply_to) SELECT $2,conversation_id,(SELECT coalesce(max(ordinal),0)+1 FROM messages WHERE conversation_id=m.conversation_id),'assistant',$3,$4,$5,request_id,$6,$1 FROM messages m WHERE id=$1").bind(mid).bind(Uuid::new_v4()).bind(value).bind(state).bind(ev).bind(hash(value.to_string())).execute(&mut **tx).await?;
    Ok(())
}
pub async fn enqueue_analyses(app: &App) -> anyhow::Result<()> {
    crate::review::enqueue(app).await?;
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7616)")
        .execute(&mut *tx)
        .await?;
    let incidents=sqlx::query("SELECT i.*,s.version AS profile_version,s.value AS profile,k.active_corpus_id,k.active_policy_version FROM incidents i CROSS JOIN app_settings s CROSS JOIN knowledge_state k WHERE s.key='ai' AND i.eligible_at<=now() AND i.evidence_version>i.analyzed_version AND i.rule_id NOT IN('R4','AI') AND NOT EXISTS(SELECT 1 FROM incident_services z JOIN services v ON v.id=z.service_id WHERE z.incident_id=i.id AND (NOT v.enabled OR v.deleted_at IS NOT NULL)) ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,i.eligible_at,i.id LIMIT 20 FOR UPDATE OF i").fetch_all(&mut *tx).await?;
    for i in incidents {
        let id = Uuid::new_v4();
        let profile: Value = i.get("profile");
        let route = route(
            &profile,
            i.get("profile_version"),
            "analysis",
            &i.get::<String, _>("rule_id"),
            false,
        );
        let incident: Uuid = i.get("id");
        sqlx::query("UPDATE analysis_jobs SET state='superseded',reason='new_evidence_version' WHERE incident_id=$1 AND kind='analysis' AND state IN('pending','preparing') AND evidence_version<$2").bind(incident).bind(i.get::<i32,_>("evidence_version")).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO analysis_jobs(id,kind,incident_id,evidence_version,provider_profile_version,provider,model,corpus_version,policy_version,snapshot_hash,snapshot,state,route,prompt_version) VALUES($1,'analysis',$2,$3,$4,$5,$6,$7,$8,'','{}','pending',$9,$10) ON CONFLICT DO NOTHING").bind(id).bind(incident).bind(i.get::<i32,_>("evidence_version")).bind(i.get::<i32,_>("profile_version")).bind(route["provider"].as_str().unwrap_or("mock")).bind(route["model"].as_str().unwrap_or("mock-v1")).bind(i.get::<Uuid,_>("active_corpus_id")).bind(i.get::<Uuid,_>("active_policy_version")).bind(&route).bind(provider::PROMPT_VERSION).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO job_services(job_id,service_id,service_version) SELECT $1,s.id,s.version FROM incident_services z JOIN services s ON s.id=z.service_id WHERE z.incident_id=$2 AND EXISTS(SELECT 1 FROM analysis_jobs WHERE id=$1) ON CONFLICT DO NOTHING").bind(id).bind(incident).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE incidents SET analyzed_version=evidence_version,pending_since=NULL WHERE id=$1",
        )
        .bind(incident)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn process(app: &App, chat_incident: Option<Uuid>) -> anyhow::Result<()> {
    let mut tx = app.pool.begin().await?;
    // Recover only work that never reserved or sent a provider request.
    sqlx::query("UPDATE analysis_jobs j SET state='pending',reason='recovered_before_dispatch',eligible_at=now() WHERE j.state='preparing' AND j.lease_until<now() AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id)").execute(&mut *tx).await?;
    // Interactive questions take precedence; row locks keep workers from claiming the same job.
    let job=sqlx::query("SELECT j.* FROM analysis_jobs j WHERE j.state='pending' AND j.eligible_at<=now() AND NOT EXISTS(SELECT 1 FROM job_services z JOIN services v ON v.id=z.service_id WHERE z.job_id=j.id AND (NOT v.enabled OR v.deleted_at IS NOT NULL)) AND (($1::uuid IS NULL AND j.kind<>'chat') OR ($1::uuid IS NOT NULL AND j.kind='chat' AND j.incident_id=$1)) ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED").bind(chat_incident).fetch_optional(&mut *tx).await?;
    let Some(j) = job else {
        return Ok(());
    };
    let jid: Uuid = j.get("id");
    sqlx::query("UPDATE analysis_jobs SET state='preparing',lease_until=now()+interval '60 seconds' WHERE id=$1").bind(jid).execute(&mut *tx).await?;
    tx.commit().await?;
    if generation_paused() {
        blocked(app, jid, "blocked_config", "generation_paused").await?;
        return Ok(());
    }
    let result = prepare(app, &j).await;
    if let Err(e) = result {
        tracing::warn!(code = "gateway_prepare_blocked");
        let code = if e.to_string().contains("context_too_large") {
            "context_too_large"
        } else {
            "embeddings_or_corpus_unavailable"
        };
        blocked(app, jid, "blocked_config", code).await?;
    }
    Ok(())
}
pub(crate) async fn blocked(app: &App, id: Uuid, state: &str, reason: &str) -> anyhow::Result<()> {
    let mut tx = app.pool.begin().await?;
    let r=sqlx::query("UPDATE analysis_jobs SET state=$2,reason=$3 WHERE id=$1 RETURNING incident_id,message_id,evidence_version,kind").bind(id).bind(state).bind(reason).fetch_one(&mut *tx).await?;
    if let Some(mid) = r.get::<Option<Uuid>, _>("message_id") {
        sqlx::query("UPDATE messages SET state=$2 WHERE id=$1")
            .bind(mid)
            .bind(state)
            .execute(&mut *tx)
            .await?;
    }
    db::emit(
        &mut tx,
        if r.get::<String, _>("kind") == "review" {
            "coverage.updated"
        } else {
            "conversation.updated"
        },
        r.get::<Option<Uuid>, _>("incident_id").unwrap_or(id),
        r.get("evidence_version"),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
async fn prepare(app: &App, j: &sqlx::postgres::PgRow) -> anyhow::Result<()> {
    if j.get::<String, _>("kind") == "review" {
        return crate::review::prepare(app, j).await;
    }
    let jid: Uuid = j.get("id");
    let incident: Uuid = j.get("incident_id");
    let kind: String = j.get("kind");
    let ev: i32 = j.get("evidence_version");
    let i = sqlx::query("SELECT * FROM incidents WHERE id=$1")
        .bind(incident)
        .fetch_one(&app.pool)
        .await?;
    let rule: String = i.get("rule_id");
    let mut selected_route: Value = j.get("route");
    if selected_route.as_object().is_none_or(|r| r.is_empty()) {
        let p: Option<Value> = sqlx::query_scalar(
            "SELECT profile FROM provider_profiles WHERE version=$1 ORDER BY id LIMIT 1",
        )
        .bind(j.get::<i32, _>("provider_profile_version"))
        .fetch_optional(&app.pool)
        .await?;
        let p = p.unwrap_or(
            json!({"provider":j.get::<String,_>("provider"),"model":j.get::<String,_>("model")}),
        );
        selected_route = route(&p, j.get("provider_profile_version"), &kind, &rule, false);
        sqlx::query("UPDATE analysis_jobs SET route=$2 WHERE id=$1")
            .bind(jid)
            .bind(&selected_route)
            .execute(&app.pool)
            .await?;
    }
    let policies: Value = sqlx::query_scalar("SELECT policies FROM policy_sets WHERE id=$1")
        .bind(j.get::<Uuid, _>("policy_version"))
        .fetch_one(&app.pool)
        .await?;
    let mut all:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',e.id,'event_type',e.event_type,'message',left(e.message,256),'source',e.source,'ingested_at',e.ingested_at,'event_time',e.event_time,'service',e.service,'user_alias',e.user_alias,'data_class',e.data_class) FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE ie.incident_id=$1 AND ie.added_version<=$2 ORDER BY e.ingest_seq").bind(incident).bind(ev).fetch_all(&app.pool).await?;
    let records: Vec<Value> = sqlx::query_scalar("SELECT DISTINCT jsonb_build_object('id',s.id,'event_type','text.record','message',s.content,'source','synthetic','service',r.service,'event_time',r.event_time,'ingested_at',r.received_at) FROM finding_segments fs JOIN review_findings f ON f.id=fs.finding_id JOIN review_segments s ON s.id=fs.segment_id JOIN text_records r ON r.id=s.record_id JOIN incident_finding_records fl ON fl.finding_id=f.id AND fl.record_id=r.id JOIN record_incidents ri ON ri.record_id=fl.record_id WHERE ri.incident_id=$1 AND r.local_reason IS NULL").bind(incident).fetch_all(&app.pool).await?;
    all.extend(records);
    let types = all
        .iter()
        .filter_map(|e| e["event_type"].as_str().map(String::from))
        .collect::<Vec<_>>();
    if rule == "R4" && kind == "chat" {
        let snapshot = json!({"events":all,"chunks":[],"policies":[],"kind":"chat","incident_id":incident,"evidence_version":ev,"omitted_count":0});
        let response = json!({"schema_version":1,"answer":"Explicación local por política: se detectó el literal hostil en un dato sintético. No se obedece ni se envía a un generador.","facts":[],"hypotheses":[],"knowledge_references":[],"uncertainty":["La regla literal no es un detector universal de instrucciones hostiles ni confirma compromiso."],"human_checks":["Revisar manualmente el texto y su procedencia sintética."]});
        let response = validate_response(response, "chat", &snapshot)?;
        let mut tx = app.pool.begin().await?;
        sqlx::query("UPDATE analysis_jobs SET state='succeeded',reason='local_policy',snapshot=$2,snapshot_hash=$3 WHERE id=$1").bind(jid).bind(&snapshot).bind(hash(snapshot.to_string())).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO analyses(id,job_id,origin,response) VALUES($1,$2,'local',$3)")
            .bind(Uuid::new_v4())
            .bind(jid)
            .bind(&response)
            .execute(&mut *tx)
            .await?;
        if let Some(mid) = j.get::<Option<Uuid>, _>("message_id") {
            insert_assistant(&mut tx, mid, &response, ev, "succeeded").await?;
            sqlx::query("UPDATE messages SET state='succeeded' WHERE id=$1")
                .bind(mid)
                .execute(&mut *tx)
                .await?;
        }
        db::emit(&mut tx, "conversation.updated", incident, ev).await?;
        tx.commit().await?;
        return Ok(());
    }
    let allowed = if rule == "AI" {
        let primary: Value = sqlx::query_scalar(
            "SELECT definition FROM review_policy ORDER BY version DESC LIMIT 1",
        )
        .fetch_one(&app.pool)
        .await?;
        primary["effect"] == "allow"
            && primary["data_class"] == "synthetic"
            && !policies.as_array().into_iter().flatten().any(|p| {
                p["definition"]["effect"] == "deny"
                    && p["definition"]["rule_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|id| id == "AI"))
            })
    } else {
        policy_allows(&policies, &kind, &rule, &types)
    };
    if !allowed
        || all
            .iter()
            .any(|e| crate::review::local_reason(e["message"].as_str().unwrap_or("")).is_some())
    {
        blocked(app, jid, "blocked_config", "policy_denied").await?;
        return Ok(());
    }
    let (question, history) = if let Some(mid) = j.get::<Option<Uuid>, _>("message_id") {
        let question: Value = sqlx::query_scalar("SELECT content FROM messages WHERE id=$1")
            .bind(mid)
            .fetch_one(&app.pool)
            .await?;
        let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('role',role,'content',content) FROM messages WHERE conversation_id=(SELECT conversation_id FROM messages WHERE id=$1) AND ordinal<(SELECT ordinal FROM messages WHERE id=$1) ORDER BY ordinal DESC LIMIT 10").bind(mid).fetch_all(&app.pool).await?;
        let mut kept = Vec::new();
        let mut bytes = 0;
        for row in rows {
            let len = row.to_string().len();
            if bytes + len > 6144 {
                break;
            }
            bytes += len;
            kept.push(row);
        }
        kept.reverse();
        (
            question["question"].as_str().unwrap_or("").to_string(),
            json!(kept),
        )
    } else {
        (String::new(), json!([]))
    };
    let services = review::job_contexts(app, jid).await?;
    let sources = review::job_source_contexts(app, jid).await?;
    let service_ids: Vec<Uuid> = services
        .iter()
        .filter_map(|v| v["id"].as_str().and_then(|x| x.parse::<Uuid>().ok()))
        .collect();
    let cve_findings = crate::cve::findings_for_services(app, &service_ids).await;
    let structure = crate::structure::context_for_services(app, &service_ids).await;
    let query = contracts::redact(
        &format!(
            "{} {} {} {} {}",
            rule,
            i.get::<String, _>("title"),
            question,
            serde_json::to_string(&services)?,
            serde_json::to_string(&sources)?
        ),
        &app.config.session_id,
    );
    let chunks = knowledge::retrieve(
        app,
        j.get("corpus_version"),
        if question.is_empty() {
            &query
        } else {
            &question
        },
        &service_ids,
    )
    .await?;
    let observability = observability::context_for_incident(
        app,
        &service_ids,
        &all.iter()
            .filter_map(|e| e["id"].as_str().and_then(|x| x.parse::<Uuid>().ok()))
            .collect::<Vec<_>>(),
    )
    .await;
    let mut events = Vec::new();
    if let Some(first) = all.first() {
        events.push(first.clone());
    }
    if all.len() > 1 {
        events.push(all.last().unwrap().clone());
    }
    for e in &all {
        if events.len() >= 50 {
            break;
        }
        if !events.iter().any(|x| x["id"] == e["id"]) {
            events.push(e.clone());
        }
    }
    let mut snapshot = json!({"schema_version":1,"kind":kind,"data_class":if job_has_real_data(app,jid).await? {"real"} else {"synthetic"},"incident_id":incident,"rule_id":rule,"evidence_version":ev,"services":services,"sources":sources,"question":question,"history":history,"events":events,"chunks":chunks,"cve_findings":cve_findings,"structure":structure,"observability":observability,"policies":policies,"corpus_version":j.get::<Uuid,_>("corpus_version"),"policy_version":j.get::<Uuid,_>("policy_version"),"profile_version":j.get::<i32,_>("provider_profile_version"),"model":j.get::<String,_>("model"),"provider":j.get::<String,_>("provider"),"route":selected_route,"prompt_version":j.get::<i32,_>("prompt_version"),"redaction_version":2,"embedding_revision":MODEL_REV,"omitted_count":all.len()-events.len()});
    while snapshot.to_string().len() > 12288 {
        // La observabilidad se reduce primero (corrección REVIEW-OBS-01): el
        // perfil resumido nunca debe costar la evidencia, los chunks ni el
        // resto del contexto útil.
        if let Some(profiles) = snapshot["observability"]["profiles"].as_array_mut() {
            let mut reduced = false;
            for p in profiles.iter_mut() {
                if p["relevant_entries"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
                {
                    p["relevant_entries"].as_array_mut().unwrap().pop();
                    let omitted = p["omitted_entries"].as_i64().unwrap_or(0) + 1;
                    p["omitted_entries"] = json!(omitted);
                    reduced = true;
                    break;
                }
            }
            if reduced {
                continue;
            }
        }
        if snapshot["observability"]["classifications"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
        {
            snapshot["observability"]["classifications"]
                .as_array_mut()
                .unwrap()
                .pop();
        } else if snapshot["history"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
        {
            snapshot["history"].as_array_mut().unwrap().remove(0);
        } else if snapshot["events"].as_array().unwrap().len() > 2 {
            snapshot["events"].as_array_mut().unwrap().pop();
            snapshot["omitted_count"] =
                json!(all.len() - snapshot["events"].as_array().unwrap().len());
        } else if snapshot["cve_findings"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
        {
            snapshot["cve_findings"].as_array_mut().unwrap().pop();
        } else if snapshot["structure"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
        {
            snapshot["structure"].as_array_mut().unwrap().pop();
        } else if snapshot["observability"]["classifications"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
        {
            snapshot["observability"]["classifications"]
                .as_array_mut()
                .unwrap()
                .pop();
        } else if snapshot["chunks"].as_array().unwrap().len() > 1 {
            snapshot["chunks"].as_array_mut().unwrap().pop();
        } else {
            anyhow::bail!("context_too_large");
        }
    }
    let snapshot: Value =
        serde_json::from_str(&redact(&snapshot.to_string(), &app.config.session_id))?;
    let h = hash(snapshot.to_string());
    let mut tx = app.pool.begin().await?;
    sqlx::query("UPDATE analysis_jobs SET snapshot=$2,snapshot_hash=$3 WHERE id=$1")
        .bind(jid)
        .bind(&snapshot)
        .bind(&h)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO retrieval_snapshots(id,job_id,corpus_id,policy_set_id,query,chunks,omitted_count) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(job_id) DO NOTHING").bind(Uuid::new_v4()).bind(jid).bind(j.get::<Uuid,_>("corpus_version")).bind(j.get::<Uuid,_>("policy_version")).bind(query).bind(&snapshot["chunks"]).bind(snapshot["omitted_count"].as_i64().unwrap_or(0) as i32).execute(&mut *tx).await?;
    let cached=sqlx::query("SELECT a.id,a.response FROM analyses a JOIN analysis_jobs j ON j.id=a.job_id WHERE j.snapshot_hash=$1 AND a.created_at>now()-interval '24 hours' AND a.origin='live' LIMIT 1").bind(&h).fetch_optional(&mut *tx).await?;
    if let Some(c) = cached {
        let value: Value = c.get("response");
        validate_response(value.clone(), &kind, &snapshot)?;
        sqlx::query("INSERT INTO analyses(id,job_id,origin,cached_from_id,response) VALUES($1,$2,'cache',$3,$4)").bind(Uuid::new_v4()).bind(jid).bind(c.get::<Uuid,_>("id")).bind(&value).execute(&mut *tx).await?;
        sqlx::query("UPDATE analysis_jobs SET state='cached' WHERE id=$1")
            .bind(jid)
            .execute(&mut *tx)
            .await?;
        if let Some(mid) = j.get::<Option<Uuid>, _>("message_id") {
            insert_assistant(&mut tx, mid, &value, ev, "cached").await?;
            sqlx::query("UPDATE messages SET state='cached' WHERE id=$1")
                .bind(mid)
                .execute(&mut *tx)
                .await?;
        }
        db::emit(&mut tx, "conversation.updated", incident, ev).await?;
        tx.commit().await?;
        return Ok(());
    }
    tx.commit().await?;
    dispatch(app, j, &snapshot, &selected_route, i.get("run_id")).await
}
pub(crate) async fn dispatch(
    app: &App,
    j: &sqlx::postgres::PgRow,
    snapshot: &Value,
    selected_route: &Value,
    _run_id: Uuid,
) -> anyhow::Result<()> {
    let jid: Uuid = j.get("id");
    if generation_paused() {
        blocked(app, jid, "blocked_config", "generation_paused").await?;
        return Ok(());
    }
    let incident: Option<Uuid> = j.get("incident_id");
    let kind: String = j.get("kind");
    let live = !["mock", "disabled"].contains(&j.get::<String, _>("provider").as_str());
    if j.get::<String, _>("provider") == "disabled" {
        blocked(app, jid, "blocked_config", "provider_not_configured").await?;
        return Ok(());
    }
    let spec = if live {
        serde_json::from_value::<provider::ModelSpec>(selected_route["spec"].clone()).ok()
    } else {
        None
    };
    if live
        && spec
            .as_ref()
            .is_none_or(|s| s.validate(&j.get::<String, _>("provider")).is_err())
    {
        blocked(
            app,
            jid,
            "blocked_config",
            "capability_tariff_or_bound_unverified",
        )
        .await?;
        return Ok(());
    }
    let key = if live {
        let id = selected_route["profile_id"]
            .as_str()
            .and_then(|s| s.parse().ok());
        match id {
            Some(id) => key_for(app, id, j.get("provider_profile_version"))
                .await
                .ok(),
            None => None,
        }
    } else {
        None
    };
    if live && key.is_none() {
        blocked(app, jid, "blocked_config", "credential_missing").await?;
        return Ok(());
    }
    let input_upper = if let Some(spec) = &spec {
        let body = provider::request_body(&j.get::<String, _>("model"), &kind, snapshot, spec);
        let bound = body.to_string().len() as u64 + 2048;
        if bound > u64::from(spec.input_cap) {
            blocked(app, jid, "blocked_config", "input_bound_exceeded").await?;
            return Ok(());
        }
        u64::from(spec.input_cap)
    } else {
        0
    };
    let worst = if let Some(spec) = &spec {
        worst_case_units(
            input_upper,
            u64::from(spec.output_cap),
            spec.input_rate_units,
            spec.output_rate_units,
        )?
    } else {
        0
    };
    if live {
        let debt: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM analysis_attempts WHERE accounted_units>reserved_units)",
        )
        .fetch_one(&app.pool)
        .await?;
        if debt {
            blocked(
                app,
                jid,
                "blocked_config",
                "billing_bound_exceeded_review_required",
            )
            .await?;
            return Ok(());
        }
    }
    let attempt = match reserve(app, jid, worst).await? {
        Some(a) => a,
        None => return Ok(()),
    };
    sqlx::query("UPDATE analysis_attempts SET state='in_flight',sent_at=now() WHERE id=$1")
        .bind(attempt)
        .execute(&app.pool)
        .await?;
    sqlx::query("UPDATE analysis_jobs SET state='in_flight' WHERE id=$1")
        .bind(jid)
        .execute(&app.pool)
        .await?;
    sqlx::query("UPDATE incidents SET last_sent_at=now() WHERE id=$1")
        .bind(incident)
        .execute(&app.pool)
        .await?;
    if std::env::var("SENTINEL_FAILPOINT").as_deref() == Ok("gateway_after_dispatch") {
        std::process::abort();
    }
    if !live {
        let value = mock_response(&kind, snapshot);
        let response = validate_response(value, &kind, snapshot)?;
        settle(app, attempt, "succeeded", Some(response), Some((0, 0))).await?;
        return Ok(());
    }
    if live {
        let result = provider::generate(
            selected_route["base_url"].as_str().unwrap_or(""),
            key.as_deref().unwrap(),
            &j.get::<String, _>("model"),
            &kind,
            snapshot,
            spec.as_ref().unwrap(),
            selected_route["workspace_id"]
                .as_str()
                .filter(|s| !s.is_empty()),
        )
        .await;
        match result {
            Ok(generation) => {
                // Usage and finish metadata are durable before domain JSON/citation validation.
                sqlx::query("UPDATE analysis_attempts SET provider_metadata=$2,input_tokens=$3,output_tokens=$4,error_code=$5 WHERE id=$1").bind(attempt).bind(&generation.metadata).bind(generation.usage.map(|u|u.0)).bind(generation.usage.map(|u|u.1)).bind(generation.error).execute(&app.pool).await?;
                if generation.error == Some("credential_rejected")
                    || generation.error == Some("usage_exceeds_bound")
                    || generation.error == Some("model_mismatch")
                    || generation.error == Some("usage_invalid")
                {
                    *app.authorization.lock().await = None;
                }
                let response = if let Some(value) = generation.content {
                    match validate_response(value.clone(), &kind, snapshot) {
                        Ok(response) => Some(response),
                        Err(error) => {
                            if kind == "review"
                                && let Ok(partial) =
                                    crate::review::validate_partial(value.clone(), snapshot)
                            {
                                sqlx::query("UPDATE analysis_attempts SET error_code='partial_coverage' WHERE id=$1").bind(attempt).execute(&app.pool).await?;
                                settle(app, attempt, "failed", Some(partial), generation.usage)
                                    .await?;
                                return Ok(());
                            }
                            let lengths = json!({"summary_chars":value["summary"].as_str().map(|s|s.chars().count()),"explanation_chars":value["explanation"].as_str().map(|s|s.chars().count()),"answer_chars":value["answer"].as_str().map(|s|s.chars().count()),"evidence_count":value["evidence"].as_array().map(Vec::len),"knowledge_refs":value["knowledge_references"].as_array().map(Vec::len),"review_shape":if kind=="review" {Some(crate::review::shape_diagnostic(&value, snapshot))} else {None}});
                            sqlx::query("UPDATE analysis_attempts SET error_code=$2,provider_metadata=provider_metadata || jsonb_build_object('validation',$3::jsonb) WHERE id=$1").bind(attempt).bind(validation_code(&error)).bind(lengths).execute(&app.pool).await?;
                            None
                        }
                    }
                } else {
                    None
                };
                let state = if response.is_some() {
                    "succeeded"
                } else if generation.usage.is_some() {
                    "failed"
                } else {
                    "unknown"
                };
                settle(app, attempt, state, response, generation.usage).await?;
            }
            Err(_) => settle(app, attempt, "unknown", None, None).await?,
        }
    }
    Ok(())
}
async fn job_has_real_data(app: &App, job: Uuid) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.id=$1 AND (EXISTS(SELECT 1 FROM review_segments z JOIN text_records r ON r.id=z.record_id WHERE z.job_id=j.id AND r.data_class='real') OR EXISTS(SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE ie.incident_id=j.incident_id AND e.data_class='real') OR EXISTS(SELECT 1 FROM record_incidents ri JOIN text_records r ON r.id=ri.record_id WHERE ri.incident_id=j.incident_id AND r.data_class='real'))) ").bind(job).fetch_one(&app.pool).await?)
}

pub async fn reserve(app: &App, job: Uuid, worst: i64) -> anyhow::Result<Option<Uuid>> {
    anyhow::ensure!(worst >= 0, "negative_reservation");
    if generation_paused() {
        blocked(app, job, "blocked_config", "generation_paused").await?;
        return Ok(None);
    }
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7616)")
        .execute(&mut *tx)
        .await?;
    // Los datos reales del laboratorio pueden salir al proveedor: se retiró el
    // permiso acotado por sesión. `real_egress` solo conserva el límite de tasa.
    let real_egress: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.id=$1 AND j.provider NOT IN ('mock','disabled') AND (EXISTS(SELECT 1 FROM review_segments z JOIN text_records r ON r.id=z.record_id WHERE z.job_id=j.id AND r.data_class='real') OR EXISTS(SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE ie.incident_id=j.incident_id AND e.data_class='real') OR EXISTS(SELECT 1 FROM record_incidents ri JOIN text_records r ON r.id=ri.record_id WHERE ri.incident_id=j.incident_id AND r.data_class='real'))) ").bind(job).fetch_one(&mut *tx).await?;
    let unassigned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM review_segments z JOIN text_records r ON r.id=z.record_id WHERE z.job_id=$1 AND r.service_id IS NULL) OR EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.id=$1 AND j.incident_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM incident_services x WHERE x.incident_id=j.incident_id))").bind(job).fetch_one(&mut *tx).await?;
    if unassigned {
        sqlx::query("UPDATE analysis_jobs SET state='blocked_config',reason='service_unassigned' WHERE id=$1 AND state IN('pending','preparing')").bind(job).execute(&mut *tx).await?;
        sqlx::query("UPDATE messages SET state='blocked_config' WHERE id=(SELECT message_id FROM analysis_jobs WHERE id=$1)").bind(job).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let unavailable:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM job_services x JOIN services s ON s.id=x.service_id WHERE x.job_id=$1 AND (NOT s.enabled OR s.deleted_at IS NOT NULL))").bind(job).fetch_one(&mut *tx).await?;
    if unavailable {
        sqlx::query("UPDATE analysis_jobs SET state='blocked_config',reason='service_inactive' WHERE id=$1 AND state IN('pending','preparing')").bind(job).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(None);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(5151)")
        .execute(&mut *tx)
        .await?;
    let guarded=sqlx::query("SELECT j.state,j.kind,j.incident_id,j.evidence_version,i.last_sent_at FROM analysis_jobs j LEFT JOIN incidents i ON i.id=j.incident_id WHERE j.id=$1 FOR UPDATE OF j").bind(job).fetch_one(&mut *tx).await?;
    if !["pending", "preparing"].contains(&guarded.get::<String, _>("state").as_str()) {
        return Ok(None);
    }
    if guarded.get::<String, _>("kind") == "analysis"
        && let Some(sent) = guarded.get::<Option<chrono::DateTime<Utc>>, _>("last_sent_at")
        && sent + chrono::Duration::seconds(60) > Utc::now()
    {
        sqlx::query("UPDATE analysis_jobs SET state='pending',eligible_at=$2,reason='cooldown_wait' WHERE id=$1").bind(job).bind(sent+chrono::Duration::seconds(60)).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let inflight: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM analysis_attempts WHERE state IN ('reserved','in_flight')",
    )
    .fetch_one(&mut *tx)
    .await?;
    if guarded.get::<String, _>("kind") != "chat" {
        let chat_waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM analysis_jobs j JOIN chat_worker_presence p ON p.incident_id=j.incident_id AND p.expires_at>now() WHERE j.kind='chat' AND j.state='pending')").fetch_one(&mut *tx).await?;
        if chat_waiting {
            sqlx::query("UPDATE analysis_jobs SET state='pending',eligible_at=now()+interval '2 seconds',reason='chat_priority' WHERE id=$1").bind(job).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(None);
        }
    }
    let circuit:bool=sqlx::query_scalar("SELECT count(*)=3 AND bool_and(state IN('failed','unknown')) AND max(finished_at)>now()-interval '60 seconds' FROM(SELECT state,finished_at FROM analysis_attempts WHERE state IN('succeeded','failed','unknown') ORDER BY finished_at DESC LIMIT 3)t").fetch_one(&mut *tx).await?;
    if circuit {
        sqlx::query("UPDATE analysis_jobs SET state='pending',eligible_at=now()+interval '60 seconds',reason='circuit_open' WHERE id=$1").bind(job).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM analysis_attempts WHERE sent_at>now()-interval '60 seconds'",
    )
    .fetch_one(&mut *tx)
    .await?;
    let unsent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM analysis_attempts WHERE state='reserved' AND sent_at IS NULL",
    )
    .fetch_one(&mut *tx)
    .await?;
    let per_minute = if real_egress { 30 } else { 6 };
    if inflight >= 3 || recent + unsent >= per_minute {
        sqlx::query("UPDATE analysis_jobs SET state='pending',eligible_at=now()+interval '10 seconds',reason='rate_limit_wait' WHERE id=$1").bind(job).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let day = Utc::now().format("%Y-%m-%d").to_string();
    sqlx::query("INSERT INTO budget_accounts(scope,scope_key,limit_units) VALUES('day',$1,200000000) ON CONFLICT DO NOTHING").bind(&day).execute(&mut *tx).await?;
    let mut accounts = vec![("day", day), ("session", app.config.session_id.clone())];
    accounts.sort();
    for (scope, key) in &accounts {
        sqlx::query("SELECT 1 FROM budget_accounts WHERE scope=$1 AND scope_key=$2 FOR UPDATE")
            .bind(scope)
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;
    }
    let cap = sqlx::query("SELECT cap_enabled,limit_units,spent_units,reserved_units,cap_baseline_spent_units FROM budget_accounts WHERE scope='session' AND scope_key=$1")
        .bind(&app.config.session_id)
        .fetch_one(&mut *tx)
        .await?;
    if worst > 0
        && cap.get::<bool, _>("cap_enabled")
        && (i128::from(cap.get::<i64, _>("spent_units"))
            - i128::from(cap.get::<i64, _>("cap_baseline_spent_units")))
            + i128::from(cap.get::<i64, _>("reserved_units"))
            + i128::from(worst)
            > i128::from(cap.get::<i64, _>("limit_units"))
    {
        sqlx::query("UPDATE analysis_jobs SET state='skipped_budget',reason='session_limit_reached' WHERE id=$1")
            .bind(job)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE messages SET state='skipped_budget' WHERE id=(SELECT message_id FROM analysis_jobs WHERE id=$1)")
            .bind(job)
            .execute(&mut *tx)
            .await?;
        db::emit(
            &mut tx,
            if guarded.get::<String, _>("kind") == "review" {
                "coverage.updated"
            } else {
                "conversation.updated"
            },
            guarded.get::<Option<Uuid>, _>("incident_id").unwrap_or(job),
            guarded.get("evidence_version"),
        )
        .await?;
        tx.commit().await?;
        return Ok(None);
    }
    let attempt = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO analysis_attempts(id,job_id,state,reserved_units) VALUES($1,$2,'reserved',$3)",
    )
    .bind(attempt)
    .bind(job)
    .bind(worst)
    .execute(&mut *tx)
    .await?;
    for (scope, key) in accounts {
        sqlx::query("UPDATE budget_accounts SET reserved_units=reserved_units+$3 WHERE scope=$1 AND scope_key=$2").bind(scope).bind(&key).bind(worst).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO budget_reservations VALUES($1,$2,$3,$4,'reserved')")
            .bind(attempt)
            .bind(scope)
            .bind(key)
            .bind(worst)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE analysis_jobs SET state='reserved' WHERE id=$1")
        .bind(job)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(attempt))
}

pub fn worst_case_units(
    input_upper: u64,
    output_cap: u64,
    input_rate_units: u64,
    output_rate_units: u64,
) -> anyhow::Result<i64> {
    let total = (u128::from(input_upper) * u128::from(input_rate_units))
        .checked_add(u128::from(output_cap) * u128::from(output_rate_units))
        .ok_or_else(|| anyhow::anyhow!("cost_overflow"))?;
    let amount = total.div_ceil(1_000_000);
    Ok(i64::try_from(amount)?)
}
pub const ROUTER_VERSION: i32 = 1;
pub fn route(profile: &Value, version: i32, kind: &str, rule: &str, deep: bool) -> Value {
    // Un borrador o un perfil deshabilitado no puede generar con una ficha
    // incompleta: se enruta a "disabled" y el despacho lo bloquea.
    let active = match profile["mode"].as_str() {
        None | Some("live") | Some("mock") => true,
        Some(_) => false,
    };
    let requested = deep || (kind == "analysis" && rule == "R2");
    let alternative = profile.get("deep_profile").filter(|p| p.is_object());
    let deep_model = profile["deep_model"].as_str().filter(|s| !s.is_empty());
    let selected = if requested {
        alternative.unwrap_or(profile)
    } else {
        profile
    };
    let resolved_deep = requested && (alternative.is_some() || deep_model.is_some());
    let model = if !active {
        "mock-v1".to_string()
    } else if resolved_deep && alternative.is_none() {
        deep_model.unwrap().to_string()
    } else {
        selected["model"].as_str().unwrap_or("mock-v1").to_string()
    };
    let profile_id = if requested && alternative.is_some() {
        Uuid::new_v5(
            &profile["id"]
                .as_str()
                .unwrap_or("00000000-0000-4000-8000-000000000002")
                .parse()
                .unwrap(),
            b"deep",
        )
        .to_string()
    } else {
        profile["id"]
            .as_str()
            .unwrap_or("00000000-0000-4000-8000-000000000002")
            .to_string()
    };
    let spec = if active {
        selected["models"]
            .get(model.as_str())
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    json!({"router_version":ROUTER_VERSION,"requested_level":if requested{"deep"}else{"standard"},"level":if resolved_deep{"deep"}else{"standard"},"reason":if requested && !resolved_deep{"Modelo profundo ausente; se eligió el estándar antes del envío"}else if deep{"Profundidad solicitada explícitamente"}else if rule=="R2"&&kind=="analysis"{"Correlación crítica de fallos y éxito"}else if kind=="review"{"Revisión primaria de todos los segmentos asignados"}else{"Explicación acotada de una incidencia"},"profile_id":profile_id,"profile_version":version,"provider":if active{selected["provider"].clone()}else{json!("disabled")},"model":model,"base_url":if active{selected["base_url"].clone()}else{json!("")},"workspace_id":if active{selected.get("workspace_id").cloned().unwrap_or(Value::Null)}else{Value::Null},"spec":spec,"prompt_version":if kind=="review"{3}else{provider::PROMPT_VERSION},"schema_version":if kind=="review"{2}else{1}})
}
#[derive(Clone, serde::Serialize)]
pub struct Authorization {
    pub run_id: Uuid,
    pub profile_version: i32,
    pub started_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub budget_units: i64,
    pub max_requests: u32,
    pub requests: u32,
    pub committed_units: i64,
}
impl Authorization {
    pub fn permits(
        &self,
        run_id: Uuid,
        profile_version: i32,
        created_at: chrono::DateTime<Utc>,
        worst: i64,
        now: chrono::DateTime<Utc>,
    ) -> bool {
        self.run_id == run_id
            && self.profile_version == profile_version
            && created_at >= self.started_at
            && now >= self.started_at
            && now < self.expires_at
            && self.requests < self.max_requests
            && worst >= 0
            && self
                .committed_units
                .checked_add(worst)
                .is_some_and(|total| total <= self.budget_units)
    }
}
pub fn usd_units(s: &str) -> anyhow::Result<i64> {
    let parts: Vec<_> = s.split('.').collect();
    anyhow::ensure!(
        parts.len() <= 2
            && !parts[0].is_empty()
            && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
            && parts.get(1).is_none_or(|p| p.len() <= 8),
        "invalid_usd"
    );
    let whole = parts[0]
        .parse::<i64>()?
        .checked_mul(100_000_000)
        .ok_or_else(|| anyhow::anyhow!("invalid_usd"))?;
    let fraction = parts
        .get(1)
        .map(|p| format!("{p:0<8}").parse::<i64>())
        .transpose()?
        .unwrap_or(0);
    whole
        .checked_add(fraction)
        .ok_or_else(|| anyhow::anyhow!("invalid_usd"))
}
pub async fn key_for(app: &App, id: Uuid, version: i32) -> anyhow::Result<String> {
    if let Some(master) = &app.config.master_key {
        if let Some(row) = sqlx::query(
            "SELECT ciphertext,nonce FROM credential_versions WHERE profile_id=$1 AND version=$2",
        )
        .bind(id)
        .bind(version)
        .fetch_optional(&app.pool)
        .await?
        {
            return crate::api::decrypt(
                master,
                &row.get::<Vec<u8>, _>("ciphertext"),
                &row.get::<Vec<u8>, _>("nonce"),
            );
        }
    } else {
        let current: i32 = sqlx::query_scalar("SELECT version FROM app_settings WHERE key='ai'")
            .fetch_one(&app.pool)
            .await?;
        anyhow::ensure!(current == version, "volatile_credential_rotated");
        if let Some(key) = app.volatile_key.lock().await.clone() {
            return Ok(key);
        }
    }
    anyhow::bail!("credential_missing")
}
#[cfg(test)]
mod router_tests {
    use super::*;
    #[test]
    fn deterministic_routing_and_explicit_fallback() {
        let mut p = json!({"id":"00000000-0000-4000-8000-000000000002","provider":"mock","model":"small","deep_model":"large"});
        assert_eq!(route(&p, 2, "analysis", "R1", false)["model"], "small");
        assert_eq!(route(&p, 2, "analysis", "R2", false)["model"], "large");
        assert_eq!(route(&p, 2, "chat", "R2", false)["model"], "small");
        assert_eq!(route(&p, 2, "chat", "R1", true)["model"], "large");
        p["deep_model"] = json!("");
        assert_eq!(route(&p, 2, "chat", "R1", true)["level"], "standard");
        p["deep_profile"] =
            json!({"provider":"claude","model":"other","base_url":"https://api.anthropic.com/v1"});
        assert_eq!(route(&p, 2, "chat", "R1", true)["provider"], "claude");
        assert_ne!(route(&p, 2, "chat", "R1", true)["profile_id"], p["id"]);
        assert_eq!(route(&p, 2, "review", "", false)["prompt_version"], 3);
        assert_eq!(route(&p, 2, "review", "", false)["schema_version"], 2);
        // Un borrador no despacha generación ni arrastra una ficha incompleta.
        p["mode"] = json!("draft");
        let draft = route(&p, 2, "chat", "R1", false);
        assert_eq!(draft["provider"], "disabled");
        assert_eq!(draft["model"], "mock-v1");
        assert!(draft["spec"].is_null());
        p["mode"] = json!("live");
        p["models"] = json!({"small": {"format":"json_object"}});
        assert_eq!(
            route(&p, 2, "chat", "R1", false)["spec"]["format"],
            "json_object"
        );
        assert_eq!(usd_units("0").unwrap(), 0);
        assert_eq!(usd_units("0.00000001").unwrap(), 1);
        assert_eq!(usd_units("1.25").unwrap(), 125_000_000);
        for invalid in ["-1", "NaN", "1e2", ".1", "1.000000001"] {
            assert!(usd_units(invalid).is_err());
        }
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn live_grant_is_scoped_timed_and_conservatively_bounded() {
        let now = Utc::now();
        let run = Uuid::new_v4();
        let mut grant = Authorization {
            run_id: run,
            profile_version: 2,
            started_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            budget_units: 100,
            max_requests: 1,
            requests: 0,
            committed_units: 40,
        };
        assert!(grant.permits(run, 2, now, 60, now));
        assert!(!grant.permits(run, 2, now, 61, now));
        assert!(!grant.permits(Uuid::new_v4(), 2, now, 0, now));
        assert!(!grant.permits(run, 3, now, 0, now));
        assert!(!grant.permits(run, 2, now - chrono::Duration::seconds(1), 0, now));
        assert!(!grant.permits(run, 2, now, 0, grant.expires_at));
        grant.requests = 1;
        assert!(!grant.permits(run, 2, now, 0, now));
    }
    #[test]
    fn money_rounds_up_without_float() {
        assert_eq!(worst_case_units(1, 0, 1, 0).unwrap(), 1);
        assert_eq!(
            worst_case_units(1_000_000, 800, 125_000_000, 250_000_000).unwrap(),
            125_200_000
        );
        assert!(worst_case_units(u64::MAX, u64::MAX, u64::MAX, u64::MAX).is_err());
    }
}
