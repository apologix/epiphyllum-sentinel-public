use epiphyllum_sentinel::*;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requiere DATABASE_URL aislada sentinel_spend_*; sin proveedor"]
async fn optional_cap_is_atomic_and_disabled_by_default() -> anyhow::Result<()> {
    let database = std::env::var("DATABASE_URL")?;
    anyhow::ensure!(
        database
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("sentinel_spend_")),
        "isolated_spend_database_required"
    );
    let pool = sqlx::PgPool::connect(&database).await?;
    sqlx::migrate!().run(&pool).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-spend-test".into(),
            origin: "http://localhost:8080".into(),
            session_id: "spend-limit-test".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    let make_job = || async {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'review',1,1,'openai','fixture','','{}','pending')")
            .bind(id)
            .execute(&app.pool)
            .await?;
        Ok::<Uuid, anyhow::Error>(id)
    };
    let uncapped = make_job().await?;
    let attempt = gateway::reserve(&app, uncapped, 100_000_001)
        .await?
        .expect("cap disabled by default");
    gateway::settle(&app, attempt, "failed", None, None).await?;
    sqlx::query("UPDATE budget_accounts SET cap_enabled=true,limit_units=10000000,cap_baseline_spent_units=spent_units WHERE scope='session' AND scope_key=$1")
        .bind(&app.config.session_id)
        .execute(&app.pool)
        .await?;
    let first = make_job().await?;
    let second = make_job().await?;
    let (a, b) = tokio::join!(
        gateway::reserve(&app, first, 6_000_000),
        gateway::reserve(&app, second, 6_000_000)
    );
    let accepted = [a?, b?].into_iter().flatten().count();
    assert_eq!(accepted, 1, "reservations share one atomic cap");
    let blocked: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis_jobs WHERE id IN($1,$2) AND state='skipped_budget' AND reason='session_limit_reached'")
        .bind(first)
        .bind(second)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(blocked, 1);
    sqlx::query(
        "UPDATE budget_accounts SET cap_enabled=false WHERE scope='session' AND scope_key=$1",
    )
    .bind(&app.config.session_id)
    .execute(&app.pool)
    .await?;
    let unbounded_again = make_job().await?;
    assert!(
        gateway::reserve(&app, unbounded_again, 20_000_000)
            .await?
            .is_some()
    );
    Ok(())
}
