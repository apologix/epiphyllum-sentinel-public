//! Run only against a newly created validation database and synthetic MCP fixture.
use epiphyllum_sentinel::*;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requiere base PostgreSQL aislada y fixture mcp-fixture:8090"]
async fn mcp_snapshot_persists_replays_and_pauses_without_fabricated_files() -> anyhow::Result<()> {
    let database = std::env::var("DATABASE_URL")?;
    anyhow::ensure!(
        database
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("sentinel_mcpcheck")
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')),
        "isolated_mcp_database_required"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "mcp-isolated-fixture".into(),
            origin: "http://localhost:8080".into(),
            session_id: "mcp-isolated-check".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    let service = Uuid::new_v4();
    let source = Uuid::new_v4();
    sqlx::query("INSERT INTO services(id,name) VALUES($1,$2)")
        .bind(service)
        .bind(format!("Servicio MCP {service}"))
        .execute(&app.pool)
        .await?;
    sqlx::query("INSERT INTO service_revisions(service_id,version,name,description,context,context_hash) VALUES($1,1,'Servicio MCP de prueba','','Contexto ficticio','test')").bind(service).execute(&app.pool).await?;
    sqlx::query("INSERT INTO sources(id,logical_name,service_id,kind,enabled,config,updated_at) VALUES($1,$2,$3,'mcp',true,$4,now()-interval '10 seconds')")
        .bind(source).bind(source.to_string()).bind(service)
        .bind(json!({"endpoint":"http://mcp-fixture:8090/mcp","resource_uri":"logs://synthetic/nginx","synthetic":true}))
        .execute(&app.pool).await?;
    mcp::poll(&app).await?;
    let records: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM text_records WHERE source_id=$1 AND service_id=$2",
    )
    .bind(source)
    .bind(service)
    .fetch_one(&app.pool)
    .await?;
    assert_eq!(records, 2);
    let locations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mcp_record_locations WHERE source_id=$1")
            .bind(source)
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(locations, 2);
    let files: i64 = sqlx::query_scalar("SELECT count(*) FROM file_instances WHERE source_id=$1")
        .bind(source)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(files, 0);
    let segments: i64 = sqlx::query_scalar("SELECT count(*) FROM review_segments s JOIN text_records r ON r.id=s.record_id WHERE r.source_id=$1").bind(source).fetch_one(&app.pool).await?;
    assert_eq!(segments, 2);
    let coverage = review::coverage(&app, None, None, Some(service), None, None).await?;
    assert_eq!(coverage["received"], 2);
    assert_eq!(coverage["units"]["eligible_records"], 2);
    assert_eq!(coverage["units"]["normalized_records"], 0);
    assert_eq!(coverage["units"]["files"], 0);
    // A DB failure must roll back records, segments, external locations and snapshot checkpoint.
    let failing_source = Uuid::new_v4();
    sqlx::query("INSERT INTO sources(id,logical_name,service_id,kind,enabled,config,updated_at) SELECT $1,$2,service_id,'mcp',true,config,now()-interval '10 seconds' FROM sources WHERE id=$3")
        .bind(failing_source).bind(failing_source.to_string()).bind(source).execute(&app.pool).await?;
    sqlx::query("CREATE FUNCTION reject_mcp_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated_mcp_failure'; END $$").execute(&app.pool).await?;
    sqlx::query("CREATE TRIGGER reject_mcp BEFORE INSERT ON review_segments FOR EACH ROW EXECUTE FUNCTION reject_mcp_test()").execute(&app.pool).await?;
    mcp::poll(&app).await?;
    sqlx::query("DROP TRIGGER reject_mcp ON review_segments")
        .execute(&app.pool)
        .await?;
    sqlx::query("DROP FUNCTION reject_mcp_test()")
        .execute(&app.pool)
        .await?;
    let rolled_back:i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM text_records WHERE source_id=$1)+(SELECT count(*) FROM mcp_captures WHERE source_id=$1)+(SELECT count(*) FROM mcp_record_locations WHERE source_id=$1)").bind(failing_source).fetch_one(&app.pool).await?;
    assert_eq!(rolled_back, 0);
    sqlx::query("UPDATE sources SET enabled=false WHERE id=$1")
        .bind(failing_source)
        .execute(&app.pool)
        .await?;
    // Administrative toggles change CAS version but never snapshot identity/capture version.
    sqlx::query("UPDATE sources SET enabled=false,version=version+1,updated_at=now()-interval '10 seconds' WHERE id=$1").bind(source).execute(&app.pool).await?;
    mcp::poll(&app).await?;
    sqlx::query("UPDATE sources SET enabled=true,version=version+1,updated_at=now()-interval '10 seconds' WHERE id=$1").bind(source).execute(&app.pool).await?;
    mcp::poll(&app).await?;
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM text_records WHERE source_id=$1")
        .bind(source)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(records, 2);
    let captures: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_captures WHERE source_id=$1")
        .bind(source)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(captures, 1);
    // Changed immutable resource is visible and cannot overwrite already captured evidence.
    sqlx::query("UPDATE mcp_captures SET content_hash='old-hash' WHERE source_id=$1")
        .bind(source)
        .execute(&app.pool)
        .await?;
    sqlx::query("UPDATE sources SET updated_at=now()-interval '10 seconds' WHERE id=$1")
        .bind(source)
        .execute(&app.pool)
        .await?;
    mcp::poll(&app).await?;
    let reason: String = sqlx::query_scalar("SELECT last_error_code FROM sources WHERE id=$1")
        .bind(source)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(reason, "mcp_resource_changed");
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM text_records WHERE source_id=$1")
        .bind(source)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(records, 2);
    Ok(())
}
