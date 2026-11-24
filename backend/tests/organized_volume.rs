//! Verificación administrativa sobre copia del volumen, sin bootstrap ni generación.
use epiphyllum_sentinel::*;
use std::sync::Arc;
#[tokio::test]
#[ignore = "requiere copia sentinel_folders_check y volumen reorganizado montado read-only"]
async fn organized_existing_logs_do_not_reingest() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    anyhow::ensure!(
        url.ends_with("/sentinel_folders_check"),
        "isolated_copy_required"
    );
    let pool = sqlx::PgPool::connect(&url).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-copy-only".into(),
            origin: "http://localhost:8080".into(),
            session_id: "organized-copy-check".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let query = "SELECT jsonb_build_object('events',(SELECT count(*) FROM events),'records',(SELECT count(*) FROM text_records),'incidents',(SELECT count(*) FROM incidents),'attempts',(SELECT count(*) FROM analysis_attempts),'evidence',(SELECT md5(string_agg(incident_id::text||event_id::text,'' ORDER BY incident_id,event_id)) FROM incident_events),'snapshots',(SELECT md5(string_agg(id::text||snapshot::text,'' ORDER BY id)) FROM analysis_jobs),'locations',(SELECT count(*) FROM record_locations),'offsets',(SELECT sum(committed_offset) FROM source_cursors))";
    let before: serde_json::Value = sqlx::query_scalar(query).fetch_one(&app.pool).await?;
    collector::poll(&app).await?;
    collector::poll(&app).await?;
    let after: serde_json::Value = sqlx::query_scalar(query).fetch_one(&app.pool).await?;
    assert_eq!(
        before, after,
        "reorganización no debe releer/duplicar ni alterar historial"
    );
    let errors:i64=sqlx::query_scalar("SELECT count(*) FROM sources WHERE enabled AND service_id IS NOT NULL AND (status<>'healthy' OR last_error_code IS NOT NULL)").fetch_one(&app.pool).await?;
    assert_eq!(errors, 0, "todas las carpetas deben quedar saludables");
    println!("ORGANIZED_COPY_OK={after}");
    Ok(())
}
