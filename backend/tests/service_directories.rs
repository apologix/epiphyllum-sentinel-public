//! Directory-scoped ingestion; run only against a disposable validation database.
use epiphyllum_sentinel::*;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requiere DATABASE_URL aislada sentinel_dirs_*; sin proveedor"]
async fn native_directory_sources_keep_cursor_and_identity() -> anyhow::Result<()> {
    let database = std::env::var("DATABASE_URL")?;
    anyhow::ensure!(
        database
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("sentinel_dirs_")),
        "isolated_directory_database_required"
    );
    let pool = sqlx::PgPool::connect(&database).await?;
    sqlx::migrate!().run(&pool).await?;
    let root = tempfile::tempdir()?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: root.path().to_string_lossy().into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-directory-test".into(),
            origin: "http://localhost:8080".into(),
            session_id: "directory-test".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    for (directory, system, protocol, line) in [
        (
            "nginx",
            "Nginx",
            "HTTP",
            "2026/10/27 03:41:10 [error] 1#1: upstream connection refused\n",
        ),
        (
            "ssh",
            "OpenSSH",
            "SSH",
            "Mar 15 02:00:01 server sshd[3821]: Failed password for root from 198.51.100.26 port 54100 ssh2\n",
        ),
    ] {
        std::fs::create_dir(root.path().join(directory))?;
        let path = root.path().join(directory).join("access.log");
        std::fs::write(&path, line)?;
        std::fs::write(path.with_extension("source.json"),json!({"schema_version":1,"synthetic":true,"run_id":Uuid::new_v4(),"sha256":hash(line),"year":2026,"timezone":"UTC"}).to_string())?;
        let service=services::create(&app,&json!({"name":directory,"description":"Fuente sintética de prueba","context":"","idempotency_key":Uuid::new_v4(),"source":{"kind":"folder","enabled":false,"config":{"root_alias":"demo-logs","directory":directory,"selector":"*.log"},"analysis":{"system":system,"protocol":protocol,"adapter":"native-text","context":"Fuente de prueba sintética","rules":[]}}})).await.unwrap();
        let source = &service["sources"]["items"][0];
        services::update_source(
            &app,
            source["id"].as_str().unwrap().parse()?,
            &json!({"expected_version":source["version"],"enabled":true}),
            false,
        )
        .await
        .unwrap();
    }
    // The same basename/glob in different configured folders is not an overlap.
    collector::poll(&app).await?;
    let rows:Vec<(String,String)>=sqlx::query_as("SELECT e.service,f.current_path FROM events e JOIN file_instances f ON f.id=e.file_instance_id ORDER BY e.service").fetch_all(&app.pool).await?;
    assert_eq!(
        rows,
        vec![
            ("nginx".into(), "nginx/access.log".into()),
            ("ssh".into(), "ssh/access.log".into())
        ]
    );
    let parsed: Vec<(String, String)> =
        sqlx::query_as("SELECT e.service,e.event_type FROM events e ORDER BY e.service")
            .fetch_all(&app.pool)
            .await?;
    assert_eq!(
        parsed,
        vec![
            ("nginx".into(), "app.error".into()),
            ("ssh".into(), "auth.failed".into())
        ]
    );
    let before: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT file_instance_id,committed_offset FROM source_cursors ORDER BY file_instance_id",
    )
    .fetch_all(&app.pool)
    .await?;
    assert_eq!(before.len(), 2);
    collector::poll(&app).await?;
    let after: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT file_instance_id,committed_offset FROM source_cursors ORDER BY file_instance_id",
    )
    .fetch_all(&app.pool)
    .await?;
    assert_eq!(before, after);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events")
            .fetch_one(&app.pool)
            .await?,
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM text_records")
            .fetch_one(&app.pool)
            .await?,
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM analysis_attempts")
            .fetch_one(&app.pool)
            .await?,
        0
    );
    Ok(())
}
