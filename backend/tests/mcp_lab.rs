//! Explicit isolated validation against the operator's laboratory VM.
use epiphyllum_sentinel::*;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requiere VM de laboratorio autorizada y base aislada sentinel_labcheck"]
async fn real_lab_records_produce_incidents_without_external_generation() -> anyhow::Result<()> {
    let database = std::env::var("DATABASE_URL")?;
    anyhow::ensure!(
        database
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("sentinel_labcheck")
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')),
        "isolated_database_required"
    );
    let pool = sqlx::PgPool::connect(&database).await?;
    sqlx::migrate!().run(&pool).await?;
    let master = "01".repeat(32);
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "isolated-lab-test-only".into(),
            origin: "http://localhost:8080".into(),
            session_id: "isolated-lab-test".into(),
            master_key: Some(master.clone()),
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    knowledge::seed(&app).await?;
    knowledge::build_pending(&app).await?;
    sqlx::query("UPDATE app_settings SET value=$1 WHERE key='ai'").bind(json!({"id":"00000000-0000-4000-8000-000000000002","provider":"mock","mode":"mock","model":"mock-v1"})).execute(&app.pool).await?;
    let endpoint = std::env::var("MCP_LAB_ENDPOINT")?;
    let ca = reqwest::Certificate::from_pem(&std::fs::read(std::env::var("MCP_LAB_CA_FILE")?)?)?;
    let builder = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca);
    let client = if let Ok(proxy) = std::env::var("MCP_LAB_PROXY") {
        builder.proxy(reqwest::Proxy::all(proxy)?)
    } else {
        builder.no_proxy()
    }
    .build()?;
    let response = client.post(&endpoint).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let config = json!({"endpoint":endpoint,"resource_uri":"logs://nginx/access","synthetic":false,"mode":"incremental_lab","poll_seconds":5});
    services::validate_config("mcp", &config).map_err(|_| anyhow::anyhow!("invalid_lab_config"))?;
    let token = std::fs::read_to_string(std::env::var("MCP_LAB_TOKEN_FILE")?)?;
    let created=services::create(&app,&json!({"name":"Nginx laboratorio","description":"Servicio de prueba","context":"Nginx de laboratorio","idempotency_key":Uuid::new_v4(),"source":{"kind":"mcp","enabled":false,"config":config,"credential":token.trim()}})).await.map_err(|_|anyhow::anyhow!("service_create_failed"))?;
    let service: Uuid = created["id"].as_str().unwrap().parse()?;
    let source_info = &created["sources"]["items"][0];
    let source: Uuid = source_info["id"].as_str().unwrap().parse()?;
    assert_eq!(source_info["service_id"], service.to_string());
    assert_eq!(source_info["data_class"], "real");
    assert_eq!(source_info["has_credential"], true);
    let checked =
        mcp::check_lab_resource(&endpoint, "logs://nginx/access", token.trim(), None).await?;
    let checked_page: serde_json::Value = serde_json::from_str(&checked)?;
    assert_eq!(checked_page["service"]["product"], "f5:nginx");
    let nginx_version = checked_page["service"]["version"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("nginx_version_missing"))?
        .to_owned();
    sqlx::query("INSERT INTO source_checks(source_id,source_version,result) VALUES($1,$2,$3)")
        .bind(source)
        .bind(source_info["version"].as_i64().unwrap() as i32)
        .bind(json!({"readable":true,"service":checked_page["service"]}))
        .execute(&app.pool)
        .await?;
    services::update_source(
        &app,
        source,
        &json!({"expected_version":source_info["version"],"enabled":true}),
        false,
    )
    .await
    .map_err(|_| anyhow::anyhow!("source_activate_failed"))?;
    sqlx::query("UPDATE sources SET updated_at=now()-interval '10 seconds' WHERE id=$1")
        .bind(source)
        .execute(&app.pool)
        .await?;
    sqlx::query("CREATE FUNCTION fail_lab_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test rollback'; END $$").execute(&app.pool).await?;
    sqlx::query("CREATE TRIGGER fail_lab_insert BEFORE INSERT ON text_records FOR EACH ROW EXECUTE FUNCTION fail_lab_insert()").execute(&app.pool).await?;
    mcp::poll(&app).await?;
    let rolled_back:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM text_records WHERE source_id=$1)+(SELECT count(*) FROM mcp_incremental_cursors WHERE source_id=$1)").bind(source).fetch_one(&app.pool).await?;
    assert_eq!(rolled_back, 0, "records and cursor must roll back together");
    sqlx::query("DROP TRIGGER fail_lab_insert ON text_records")
        .execute(&app.pool)
        .await?;
    sqlx::query("DROP FUNCTION fail_lab_insert()")
        .execute(&app.pool)
        .await?;
    sqlx::query("UPDATE sources SET updated_at=now()-interval '10 seconds' WHERE id=$1")
        .bind(source)
        .execute(&app.pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    mcp::poll(&app).await?;
    let status: (String, Option<String>) =
        sqlx::query_as("SELECT status,last_error_code FROM sources WHERE id=$1")
            .bind(source)
            .fetch_one(&app.pool)
            .await?;
    anyhow::ensure!(status.0 == "healthy", "source failed: {:?}", status.1);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE source_id=$1 AND data_class='real'")
            .bind(source)
            .fetch_one(&app.pool)
            .await?;
    assert!(count >= 20, "expected lab events, found {count}");
    let class_counts:Vec<(String,i64)>=sqlx::query_as("SELECT event_type,count(*) FROM events WHERE source_id=$1 GROUP BY event_type ORDER BY event_type").bind(source).fetch_all(&app.pool).await?;
    println!("Tipos normalizados: {class_counts:?}");
    detection::drain(&app).await?;
    let rules: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT rule_id FROM incidents ORDER BY rule_id")
            .fetch_all(&app.pool)
            .await?;
    println!("Reglas detectadas: {rules:?}");
    for rule in ["R1", "R2", "R3"] {
        assert!(rules.iter().any(|r| r == rule), "missing {rule}");
    }
    let original_count:i64=sqlx::query_scalar("SELECT count(*) FROM text_records WHERE source_id=$1 AND (data_class<>'real' OR original IS NOT NULL OR safe_text IS NOT NULL)").bind(source).fetch_one(&app.pool).await?;
    assert_eq!(original_count, 0);
    let cursor: Option<String> =
        sqlx::query_scalar("SELECT cursor FROM mcp_incremental_cursors WHERE source_id=$1")
            .bind(source)
            .fetch_one(&app.pool)
            .await?;
    assert!(cursor.is_some());
    sqlx::query("UPDATE sources SET updated_at=now()-interval '10 seconds' WHERE id=$1")
        .bind(source)
        .execute(&app.pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    mcp::poll(&app).await?;
    let again: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE source_id=$1")
        .bind(source)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(count, again, "replay must not duplicate events");
    review::enqueue(&app).await?;
    gateway::process(&app, None).await?;
    let mock: i64 = sqlx::query_scalar("SELECT count(*) FROM analyses WHERE origin='mock'")
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(mock, 1, "expected primary review using mock and local RAG");
    let retrieval: i64 = sqlx::query_scalar("SELECT count(*) FROM retrieval_snapshots")
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(retrieval, 1);
    println!("Revisión primaria: generación simulada, recuperación vectorial local real");
    let external_job = Uuid::new_v4();
    sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'review',1,1,'openai','not-sent','','{}','pending')").bind(external_job).execute(&app.pool).await?;
    sqlx::query("UPDATE review_segments SET job_id=$1 WHERE id=(SELECT s.id FROM review_segments s JOIN text_records r ON r.id=s.record_id WHERE r.source_id=$2 AND s.job_id IS NULL LIMIT 1)").bind(external_job).bind(source).execute(&app.pool).await?;
    // Se retiró el permiso acotado de datos reales: la revisión de un registro
    // real del laboratorio ya puede reservar y despacharse.
    assert!(
        gateway::reserve(&app, external_job, 0).await?.is_some(),
        "la revisión de datos reales ya no debe bloquearse por egress"
    );
    let attempts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis_attempts WHERE job_id=$1")
            .bind(external_job)
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(attempts, 1);
    let software: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT software_product,software_version,software_origin FROM services WHERE id=$1",
    )
    .bind(service)
    .fetch_one(&app.pool)
    .await?;
    assert_eq!(
        software,
        (
            Some("f5:nginx".into()),
            Some(nginx_version.clone()),
            Some("mcp".into())
        )
    );
    for uri in [
        "logs://nginx/error",
        "logs://mysql/error",
        "logs://mysql/audit",
        "logs://node/app",
        "logs://node/security",
        "logs://ssh/auth",
    ] {
        let config = json!({"endpoint":endpoint,"resource_uri":uri,"synthetic":false,"mode":"incremental_lab","poll_seconds":5});
        let checked = mcp::check_lab_resource(&endpoint, uri, token.trim(), None).await?;
        let page: serde_json::Value = serde_json::from_str(&checked)?;
        let expected_records = page["records"].as_array().map_or(0, Vec::len) as i64;
        let created = services::create(
            &app,
            &json!({
            "name":format!("VM recurso {uri}"),"description":"","context":"","idempotency_key":Uuid::new_v4(),
                "source":{"kind":"mcp","enabled":false,"config":config,"credential":token.trim()}
            }),
        )
        .await
        .map_err(|_| anyhow::anyhow!("service_create_failed_for_{uri}"))?;
        let other_service: Uuid = created["id"].as_str().unwrap().parse()?;
        let source_info = &created["sources"]["items"][0];
        let other_source: Uuid = source_info["id"].as_str().unwrap().parse()?;
        sqlx::query("INSERT INTO source_checks(source_id,source_version,result) VALUES($1,$2,$3)")
            .bind(other_source)
            .bind(1_i32)
            .bind(json!({"readable":true,"service":page["service"]}))
            .execute(&app.pool)
            .await?;
        services::update_source(
            &app,
            other_source,
            &json!({"expected_version":1,"enabled":true}),
            false,
        )
        .await
        .map_err(|_| anyhow::anyhow!("source_activate_failed_for_{uri}"))?;
        sqlx::query("UPDATE sources SET updated_at=now()-interval '10 seconds' WHERE id=$1")
            .bind(other_source)
            .execute(&app.pool)
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        mcp::poll(&app).await?;
        let state: (String, Option<String>) =
            sqlx::query_as("SELECT status,last_error_code FROM sources WHERE id=$1")
                .bind(other_source)
                .fetch_one(&app.pool)
                .await?;
        anyhow::ensure!(state.0 == "healthy", "{uri}: {:?}", state.1);
        let records: i64 =
            sqlx::query_scalar("SELECT count(*) FROM text_records WHERE source_id=$1")
                .bind(other_source)
                .fetch_one(&app.pool)
                .await?;
        anyhow::ensure!(
            records >= expected_records,
            "{uri}: fewer records than the MCP page"
        );
        let expected_product = mcp::lab_resource(uri).unwrap().1[0];
        let actual: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT software_product,software_version FROM services WHERE id=$1")
                .bind(other_service)
                .fetch_one(&app.pool)
                .await?;
        if uri.starts_with("logs://nginx/") {
            assert_eq!(
                actual,
                (Some(expected_product.into()), Some(nginx_version.clone()))
            );
        } else {
            assert_eq!(
                actual,
                (None, None),
                "no installed service should not claim a version"
            );
        }
        println!("{uri}: {records} registros, estado {}", state.0);
    }
    Ok(())
}
