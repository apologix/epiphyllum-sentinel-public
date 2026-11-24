use crate::*;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
pub async fn emit(
    tx: &mut Transaction<'_, Postgres>,
    kind: &str,
    id: Uuid,
    version: i32,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO outbox_events(kind,aggregate_id,aggregate_version,payload) VALUES($1,$2,$3,$4)").bind(kind).bind(id).bind(version).bind(json!({"schema_version":1,"id":id,"version":version})).execute(&mut **tx).await?;
    Ok(())
}
pub async fn rows(pool: &sqlx::PgPool, query: &str) -> anyhow::Result<Vec<Value>> {
    Ok(sqlx::query_scalar::<_, Value>(query)
        .fetch_all(pool)
        .await?)
}
pub async fn bootstrap(app: &App) -> anyhow::Result<()> {
    for (id, threshold, window) in [("R1", 5, 60), ("R2", 5, 120), ("R3", 10, 30), ("R4", 1, 0)] {
        let def = json!({"id":id,"version":1,"threshold":threshold,"window_seconds":window});
        sqlx::query("INSERT INTO rule_versions VALUES($1,1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(id)
            .bind(&def)
            .bind(hash(def.to_string()))
            .execute(&app.pool)
            .await?;
    }
    sqlx::query("INSERT INTO sources(id,logical_name) VALUES('00000000-0000-4000-8000-000000000001','demo-logs') ON CONFLICT DO NOTHING").execute(&app.pool).await?;
    sqlx::query("INSERT INTO app_settings(key,value) VALUES('ai',$1) ON CONFLICT DO NOTHING").bind(json!({"id":"00000000-0000-4000-8000-000000000002","name":"Perfil local","mode":"disabled","provider":"disabled","base_url":"https://api.openai.com/v1","model":"","json_mode":true})).execute(&app.pool).await?;
    for (scope, key, limit) in [
        ("session", app.config.session_id.clone(), 100_000_000_i64),
        (
            "day",
            chrono::Utc::now().format("%Y-%m-%d").to_string(),
            200_000_000,
        ),
    ] {
        sqlx::query("INSERT INTO budget_accounts(scope,scope_key,limit_units) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(scope).bind(key).bind(limit).execute(&app.pool).await?;
    }
    // Any previously dispatched request may have incurred cost. Never resend it.
    let attempts: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM analysis_attempts WHERE state IN ('in_flight','reserved')",
    )
    .fetch_all(&app.pool)
    .await?;
    for attempt in attempts {
        crate::gateway::settle(app, attempt, "unknown", None, None).await?;
    }
    sqlx::query("UPDATE analysis_jobs SET state='pending', reason='recovered_before_dispatch' WHERE state='preparing'").execute(&app.pool).await?;
    sqlx::query("UPDATE analysis_jobs j SET state='pending',reason='automatic_processing_restored',eligible_at=now() WHERE j.state='blocked_config' AND j.reason='live_not_authorized_or_scope_exhausted' AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id) AND j.provider_profile_version=(SELECT version FROM app_settings WHERE key='ai')").execute(&app.pool).await?;
    sqlx::query("UPDATE analysis_jobs j SET state='pending',reason='automatic_api_review',eligible_at=now() WHERE j.kind='review' AND ((j.state='blocked_config' AND j.reason='live_not_authorized_or_scope_exhausted') OR j.state='skipped_budget') AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=j.id) AND j.provider_profile_version=(SELECT version FROM app_settings WHERE key='ai')").execute(&app.pool).await?;
    // Se retiró el permiso acotado de datos reales: los trabajos que quedaron
    // bloqueados por ese motivo vuelven a la cola. Nunca se reenvía un intento
    // que ya existió.
    sqlx::query("UPDATE analysis_jobs SET state='pending',reason='real_data_egress_enabled',eligible_at=now() WHERE state='blocked_config' AND reason='real_data_egress_disabled' AND NOT EXISTS(SELECT 1 FROM analysis_attempts a WHERE a.job_id=analysis_jobs.id)").execute(&app.pool).await?;
    Ok(())
}

pub async fn schema_probe(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let _=sqlx::query!("SELECT active_corpus_id, active_policy_version, version FROM knowledge_state WHERE singleton = true").fetch_optional(pool).await?;
    Ok(())
}
