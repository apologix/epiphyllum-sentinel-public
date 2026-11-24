use epiphyllum_sentinel::*;
use std::sync::Arc;
use uuid::Uuid;
#[tokio::test]
#[ignore = "requiere base aislada DATABASE_URL y GENERATION_PAUSED=1"]
async fn maintenance_never_reserves_or_sends() -> anyhow::Result<()> {
    assert!(gateway::generation_paused());
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::migrate!().run(&pool).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-maintenance-only".into(),
            origin: "http://localhost:8080".into(),
            session_id: "paused-maintenance-check".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let job = Uuid::new_v4();
    sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'review',1,1,'openai','fixture','','{}','pending')").bind(job).execute(&app.pool).await?;
    assert!(gateway::reserve(&app, job, 100_000_000).await?.is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM analysis_attempts WHERE job_id=$1")
            .bind(job)
            .fetch_one(&app.pool)
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT reason FROM analysis_jobs WHERE id=$1")
            .bind(job)
            .fetch_one(&app.pool)
            .await?,
        "generation_paused"
    );
    sqlx::query("UPDATE analysis_jobs SET state='pending' WHERE id=$1")
        .bind(job)
        .execute(&app.pool)
        .await?;
    gateway::process(&app, None).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT reason FROM analysis_jobs WHERE id=$1")
            .bind(job)
            .fetch_one(&app.pool)
            .await?,
        "generation_paused"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM analysis_attempts WHERE job_id=$1")
            .bind(job)
            .fetch_one(&app.pool)
            .await?,
        0
    );
    Ok(())
}
