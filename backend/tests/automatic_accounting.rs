use epiphyllum_sentinel::*;
use std::sync::Arc;
use uuid::Uuid;
#[tokio::test]
#[ignore = "requiere PostgreSQL aislado; no llama a proveedores"]
async fn automatic_accounting_without_cap() -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "isolated-accounting-secret".into(),
            origin: "http://localhost:8080".into(),
            session_id: "automatic-accounting-test".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    let job = Uuid::new_v4();
    sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'review',1,1,'openai','fixture','x','{}','pending')").bind(job).execute(&app.pool).await?;
    let attempt = gateway::reserve(&app, job, 100_000_001)
        .await?
        .expect("la contabilidad no impone tope");
    sqlx::query("UPDATE analysis_attempts SET state='in_flight' WHERE id=$1")
        .bind(attempt)
        .execute(&app.pool)
        .await?;
    db::bootstrap(&app).await?;
    let state: String = sqlx::query_scalar("SELECT state FROM analysis_jobs WHERE id=$1")
        .bind(job)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(state, "unknown");
    let spent: i64 = sqlx::query_scalar(
        "SELECT spent_units FROM budget_accounts WHERE scope='session' AND scope_key=$1",
    )
    .bind(&app.config.session_id)
    .fetch_one(&app.pool)
    .await?;
    assert_eq!(spent, 100_000_001);
    db::bootstrap(&app).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis_attempts WHERE job_id=$1")
        .bind(job)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(count, 1);
    let never_sent = Uuid::new_v4();
    sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state,reason) VALUES($1,'review',1,1,'openai','fixture','x','{}','blocked_config','live_not_authorized_or_scope_exhausted')").bind(never_sent).execute(&app.pool).await?;
    db::bootstrap(&app).await?;
    let status: String = sqlx::query_scalar("SELECT state FROM analysis_jobs WHERE id=$1")
        .bind(never_sent)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(status, "pending");
    assert!(app.authorization.lock().await.is_none());
    let mut concurrent = Vec::new();
    for _ in 0..4 {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'review',1,1,'openai','fixture','x','{}','pending')").bind(id).execute(&app.pool).await?;
        concurrent.push(id);
    }
    let results =
        futures_util::future::join_all(concurrent.iter().map(|id| gateway::reserve(&app, *id, 1)))
            .await;
    let accepted = results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .count();
    assert_eq!(
        accepted, 3,
        "hasta tres solicitudes pueden reservarse en paralelo"
    );
    Ok(())
}
