use epiphyllum_sentinel::*;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--init-secrets") {
        return secrets::initialize();
    }
    if std::env::args().nth(1).as_deref() == Some("--migrate-only") {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
        sqlx::migrate!().run(&pool).await?;
        println!("Migraciones aplicadas sin iniciar workers ni generación.");
        return Ok(());
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("epiphyllum_sentinel=info")
        .init();
    let config = Config {
        log_root: std::env::var("LOG_ROOT").unwrap_or("/data/logs".into()),
        embeddings_url: std::env::var("EMBEDDINGS_URL").unwrap_or("http://embeddings:8001".into()),
        admin_secret: secrets::read("ADMIN_SECRET", "admin_secret")?,
        origin: std::env::var("APP_ORIGIN").unwrap_or("http://localhost:8080".into()),
        session_id: std::env::var("DEMO_SESSION_ID")
            .unwrap_or("00000000-0000-4000-8000-000000000042".into()),
        master_key: secrets::read("MASTER_KEY", "master_key")
            .ok()
            .filter(|s| !s.is_empty()),
    };
    anyhow::ensure!(
        config.admin_secret.len() >= 16,
        "ADMIN_SECRET debe tener al menos 16 caracteres"
    );
    anyhow::ensure!(
        config.log_root == "/data/logs",
        "LOG_ROOT debe ser el volumen sintético /data/logs"
    );
    if let Some(key) = &config.master_key {
        anyhow::ensure!(
            hex::decode(key)?.len() == 32,
            "MASTER_KEY debe tener 32 bytes hex"
        );
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(&std::env::var("DATABASE_URL")?)?;
    let app = App {
        pool,
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?,
        config: Arc::new(config),
        volatile_key: Arc::new(Mutex::new(None)),
        authorization: Arc::new(Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let startup = app.clone();
    tokio::spawn(async move {
        loop {
            match start_workers(startup.clone()).await {
                Ok(()) => break,
                Err(_) => {
                    tracing::warn!(code = "startup_dependency_blocked");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    tracing::info!(
        code = "backend_started",
        mode = "automatic_without_budget_cap"
    );
    axum::serve(listener, api::router(app))
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal");
            tokio::select! { _ = tokio::signal::ctrl_c() => (), _ = term.recv() => () }
        })
        .await?;
    Ok(())
}

async fn start_workers(app: App) -> anyhow::Result<()> {
    sqlx::migrate!().run(&app.pool).await?;
    let mut leader = app.pool.acquire().await?;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(20261112)")
        .fetch_one(&mut *leader)
        .await?;
    anyhow::ensure!(got, "Ya existe un procesador activo");
    db::schema_probe(&app.pool).await?;
    db::bootstrap(&app).await?;
    knowledge::seed(&app).await?;
    app.leadership
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let worker = app.clone();
    tokio::spawn(async move {
        let mut leadership_connection = Some(leader);
        loop {
            if let Some(conn) = &mut leadership_connection
                && sqlx::query("SELECT 1").execute(&mut **conn).await.is_err()
            {
                leadership_connection = None;
                worker
                    .leadership
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
            if leadership_connection.is_none()
                && let Ok(mut conn) = worker.pool.acquire().await
                && sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock(20261112)")
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap_or(false)
            {
                leadership_connection = Some(conn);
                worker
                    .leadership
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if !worker.leadership.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            for (code, result) in [
                ("ingestion", collector::poll(&worker).await),
                ("detection", detection::drain(&worker).await),
                ("analysis_enqueue", gateway::enqueue_analyses(&worker).await),
            ] {
                if result.is_err() {
                    tracing::warn!(code);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
    let mcp_worker = app.clone();
    tokio::spawn(async move {
        loop {
            if mcp_worker
                .leadership
                .load(std::sync::atomic::Ordering::SeqCst)
                && mcp::poll(&mcp_worker).await.is_err()
            {
                tracing::warn!(code = "mcp_ingestion");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    let worker = app.clone();
    tokio::spawn(async move {
        loop {
            if worker.leadership.load(std::sync::atomic::Ordering::SeqCst)
                && knowledge::build_pending(&worker).await.is_err()
            {
                tracing::warn!(code = "knowledge_unavailable");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    for _ in 0..3 {
        let worker = app.clone();
        tokio::spawn(async move {
            loop {
                if worker.leadership.load(std::sync::atomic::Ordering::SeqCst)
                    && gateway::process(&worker, None).await.is_err()
                {
                    tracing::warn!(code = "generation_unavailable");
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }
    let supervisor = app.clone();
    tokio::spawn(async move {
        let mut chats = std::collections::HashMap::<uuid::Uuid, tokio::task::JoinHandle<()>>::new();
        loop {
            chats.retain(|_, task| !task.is_finished());
            if supervisor
                .leadership
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                if let Ok(active) = sqlx::query_scalar::<_, uuid::Uuid>(
                    "SELECT DISTINCT incident_id FROM chat_worker_presence WHERE expires_at>now()
                     UNION
                     SELECT DISTINCT incident_id FROM analysis_jobs WHERE kind='chat' AND state='pending' AND created_at>now()-interval '15 minutes'",
                )
                .fetch_all(&supervisor.pool)
                .await
                {
                    for incident in active {
                        chats.entry(incident).or_insert_with(|| {
                            let worker = supervisor.clone();
                            tokio::spawn(async move {
                                loop {
                                    if !worker.leadership.load(std::sync::atomic::Ordering::SeqCst) { break; }
                                    // Una pregunta ya enviada no debe quedar huérfana si la
                                    // pestaña pierde presencia: se procesa durante 15 minutos.
                                    let active = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM chat_worker_presence WHERE incident_id=$1 AND expires_at>now()) OR EXISTS(SELECT 1 FROM analysis_jobs WHERE kind='chat' AND state='pending' AND incident_id=$1 AND created_at>now()-interval '15 minutes')").bind(incident).fetch_one(&worker.pool).await.unwrap_or(false);
                                    if !active { break; }
                                    if gateway::process(&worker, Some(incident)).await.is_err() {
                                        tracing::warn!(code = "chat_generation_unavailable");
                                    }
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                }
                            })
                        });
                    }
                }
                let _ = sqlx::query(
                    "DELETE FROM chat_worker_presence WHERE expires_at<now()-interval '5 minutes'",
                )
                .execute(&supervisor.pool)
                .await;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    let cleanup = app.clone();
    tokio::spawn(async move {
        loop {
            if retention::prune(&cleanup).await.is_err() {
                tracing::warn!(code = "retention_unavailable");
            }
            tokio::time::sleep(Duration::from_secs(86400)).await;
        }
    });
    let cve_explain_worker = app.clone();
    tokio::spawn(async move {
        loop {
            if cve_explain_worker
                .leadership
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                crate::cve::process_explanations(&cve_explain_worker).await;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    let cve_worker = app.clone();
    tokio::spawn(async move {
        loop {
            if cve_worker
                .leadership
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                crate::cve::due_checks(&cve_worker).await;
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    Ok(())
}
