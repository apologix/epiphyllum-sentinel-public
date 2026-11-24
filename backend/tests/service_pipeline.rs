use epiphyllum_sentinel::*;
use serde_json::{Value, json};
use sqlx::Row;
use std::{io::Write, sync::Arc};
use uuid::Uuid;

async fn count(app: &App, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(&app.pool).await.unwrap()
}
async fn configured(app: &App, name: &str, file: &str) -> (Uuid, Uuid) {
    let s=services::create(app,&json!({"name":name,"description":"Servicio sintético","context":"Primera guía del servicio","idempotency_key":Uuid::new_v4(),"source":{"kind":"folder","config":{"root_alias":"demo-logs","selector":file},"enabled":false}})).await.unwrap();
    let id = s["id"].as_str().unwrap().parse().unwrap();
    let source = s["sources"]["items"][0].clone();
    let source_id = source["id"].as_str().unwrap().parse().unwrap();
    services::update_source(
        app,
        source_id,
        &json!({"expected_version":source["version"],"enabled":true}),
        false,
    )
    .await
    .unwrap();
    (id, source_id)
}
fn write_event(file: &mut std::fs::File, run: Uuid, n: u64, kind: &str) {
    writeln!(file,"{}",json!({"schema_version":1,"scenario_run_id":run,"event_id":Uuid::new_v5(&run,&n.to_be_bytes()),"seq":n+1,"timestamp":"2026-11-13T12:00:00Z","source":"app","event_type":kind,"level":"error","service":"INTENTO DE REASIGNACIÓN","message":"audit logging disabled","src_ip":"192.0.2.10","user":"demo-test"})).unwrap();
}
#[tokio::test]
#[ignore = "requiere PostgreSQL/pgvector/E5 aislados, sin proveedor"]
async fn configured_sources_lifecycle_and_real_rag() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::migrate!().run(&pool).await?;
    let dir = tempfile::tempdir()?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: dir.path().to_string_lossy().into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-service-secret".into(),
            origin: "http://localhost:8080".into(),
            session_id: "service-pipeline-test".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    knowledge::seed(&app).await?;
    knowledge::build_pending(&app).await?;
    // Explicit mock profile only in this disposable database. Retrieval stays real.
    sqlx::query("UPDATE app_settings SET value=$1 WHERE key='ai'").bind(json!({"id":"00000000-0000-4000-8000-000000000002","provider":"mock","mode":"mock","model":"mock-v1"})).execute(&app.pool).await?;
    let (a, source_a) = configured(&app, "Nginx A", "a.ndjson").await;
    let (b, _) = configured(&app, "Nginx B", "b.ndjson").await;
    let run = Uuid::new_v4();
    let mut af = std::fs::File::create(dir.path().join("a.ndjson"))?;
    let mut bf = std::fs::File::create(dir.path().join("b.ndjson"))?;
    for n in 0..10 {
        write_event(&mut af, run, n, "app.error");
        write_event(&mut bf, run, n + 10, "app.error");
    }
    collector::poll(&app).await?;
    detection::drain(&app).await?;
    assert_eq!(count(&app, "SELECT count(*) FROM events").await, 20);
    assert_eq!(
        count(
            &app,
            "SELECT count(*) FROM services WHERE name='INTENTO DE REASIGNACIÓN'"
        )
        .await,
        0
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM incidents WHERE rule_id='R3'").await,
        2
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM incident_services").await,
        2
    );
    let associations: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT service_id FROM events ORDER BY service_id")
            .fetch_all(&app.pool)
            .await?;
    assert!(associations.contains(&a) && associations.contains(&b));
    collector::poll(&app).await?;
    assert_eq!(count(&app, "SELECT count(*) FROM events").await, 20);
    review::enqueue(&app).await?;
    let original_job: Uuid = sqlx::query_scalar(
        "SELECT id FROM analysis_jobs WHERE kind='review' ORDER BY created_at LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await?;
    let owner: Uuid = sqlx::query_scalar("SELECT service_id FROM job_services WHERE job_id=$1")
        .bind(original_job)
        .fetch_one(&app.pool)
        .await?;
    let old = services::detail(&app, owner).await.unwrap();
    let changed=services::update(&app,owner,&json!({"expected_version":old["version"],"name":"Nombre actualizado","context":"Segunda guía diferente"}),false).await.unwrap();
    assert_eq!(
        review::job_contexts(&app, original_job).await?[0]["context"],
        "Primera guía del servicio"
    );
    let paused = services::update(
        &app,
        owner,
        &json!({"expected_version":changed["version"],"enabled":false}),
        false,
    )
    .await
    .unwrap();
    assert!(gateway::reserve(&app, original_job, 0).await?.is_none());
    assert_eq!(
        count(&app, "SELECT count(*) FROM analysis_attempts").await,
        0
    );
    let resumed = services::update(
        &app,
        owner,
        &json!({"expected_version":paused["version"],"enabled":true}),
        false,
    )
    .await
    .unwrap();
    gateway::process(&app, None).await?;
    let job = sqlx::query("SELECT state,snapshot FROM analysis_jobs WHERE id=$1")
        .bind(original_job)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(job.get::<String, _>("state"), "succeeded");
    let snapshot: Value = job.get("snapshot");
    assert_eq!(
        snapshot["services"][0]["context"],
        "Primera guía del servicio"
    );
    assert!(
        snapshot["chunks"].as_array().is_some_and(|c| !c.is_empty()),
        "embeddings y pgvector reales"
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM analyses WHERE origin='mock'").await,
        1
    );
    assert_eq!(
        count(
            &app,
            "SELECT coalesce(sum(accounted_units),0)::bigint FROM analysis_attempts"
        )
        .await,
        0
    );
    // Renaming does not split an active deterministic incident.
    write_event(&mut af, run, 20, "app.error");
    collector::poll(&app).await?;
    detection::drain(&app).await?;
    assert_eq!(
        count(&app, "SELECT count(*) FROM incidents WHERE rule_id='R3'").await,
        2
    );
    // Pause service A and preserve its cursor while new bytes arrive.
    let current = services::detail(&app, a).await.unwrap();
    let current = services::update(
        &app,
        a,
        &json!({"expected_version":current["version"],"enabled":false}),
        false,
    )
    .await
    .unwrap();
    write_event(&mut af, run, 21, "app.error");
    collector::poll(&app).await?;
    assert_eq!(count(&app, "SELECT count(*) FROM events").await, 21);
    services::update(
        &app,
        a,
        &json!({"expected_version":current["version"],"enabled":true}),
        false,
    )
    .await
    .unwrap();
    collector::poll(&app).await?;
    assert_eq!(count(&app, "SELECT count(*) FROM events").await, 22);
    // Source toggles keep the capture identity, including unparsed records.
    writeln!(af, "synthetic unparsed notice")?;
    collector::poll(&app).await?;
    let before = count(&app, "SELECT count(*) FROM text_records").await;
    let source = services::source_detail(&app, source_a).await.unwrap();
    let source = services::update_source(
        &app,
        source_a,
        &json!({"expected_version":source["version"],"enabled":false}),
        false,
    )
    .await
    .unwrap();
    services::update_source(
        &app,
        source_a,
        &json!({"expected_version":source["version"],"enabled":true}),
        false,
    )
    .await
    .unwrap();
    collector::poll(&app).await?;
    assert_eq!(
        count(&app, "SELECT count(*) FROM text_records").await,
        before
    );
    let current = services::detail(&app, owner).await.unwrap();
    services::update(
        &app,
        owner,
        &json!({"expected_version":current["version"]}),
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        review::job_contexts(&app, original_job).await?[0]["context"],
        "Primera guía del servicio"
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM analyses WHERE origin='mock'").await,
        1
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM text_records").await,
        before
    );
    db::bootstrap(&app).await?;
    collector::poll(&app).await?;
    assert_eq!(
        count(&app, "SELECT count(*) FROM text_records").await,
        before
    );
    assert!(resumed["enabled"].as_bool().unwrap());
    Ok(())
}

async fn waiting_for_lifecycle(pool: &sqlx::PgPool, expected: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=7616 AND NOT granted")
                .fetch_one(pool).await.unwrap();
            if waiting >= expected { break; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await.expect("workers must reach the lifecycle lock");
}

#[tokio::test]
#[ignore = "requiere RACE_DATABASE_URL aislada; no envía solicitudes externas"]
async fn lifecycle_serializes_both_orders_of_reservation() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("RACE_DATABASE_URL")?).await?;
    sqlx::migrate!().run(&pool).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-race-only".into(),
            origin: "http://localhost:8080".into(),
            session_id: "lifecycle-race".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    let service = services::create(&app, &json!({"name":"Servicio carrera","description":"","context":"","idempotency_key":Uuid::new_v4()})).await.unwrap();
    let id: Uuid = service["id"].as_str().unwrap().parse()?;
    let mut version = 1;
    for pause_first in [true, false] {
        let job = Uuid::new_v4();
        sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'review',1,1,'mock','mock-v1','','{}','pending')").bind(job).execute(&app.pool).await?;
        sqlx::query("INSERT INTO job_services VALUES($1,$2,$3)")
            .bind(job)
            .bind(id)
            .bind(version)
            .execute(&app.pool)
            .await?;
        let mut gate = app.pool.begin().await?;
        services::lock(&mut gate).await?;
        let pause_app = app.clone();
        let reserve_app = app.clone();
        let (pause, reserve) = if pause_first {
            let pause = tokio::spawn(async move {
                services::update(
                    &pause_app,
                    id,
                    &json!({"expected_version":version,"enabled":false}),
                    false,
                )
                .await
                .unwrap()
            });
            waiting_for_lifecycle(&app.pool, 1).await;
            let reserve =
                tokio::spawn(async move { gateway::reserve(&reserve_app, job, 0).await.unwrap() });
            (pause, reserve)
        } else {
            let reserve =
                tokio::spawn(async move { gateway::reserve(&reserve_app, job, 0).await.unwrap() });
            waiting_for_lifecycle(&app.pool, 1).await;
            let pause = tokio::spawn(async move {
                services::update(
                    &pause_app,
                    id,
                    &json!({"expected_version":version,"enabled":false}),
                    false,
                )
                .await
                .unwrap()
            });
            (pause, reserve)
        };
        waiting_for_lifecycle(&app.pool, 2).await;
        gate.commit().await?;
        pause.await?;
        let attempt = reserve.await?;
        if pause_first {
            assert!(attempt.is_none());
            assert_eq!(
                sqlx::query_scalar::<_, String>("SELECT reason FROM analysis_jobs WHERE id=$1")
                    .bind(job)
                    .fetch_one(&app.pool)
                    .await?,
                "service_inactive"
            );
        } else {
            let attempt = attempt.expect("reservation crossed durable boundary before pause");
            assert_eq!(
                sqlx::query_scalar::<_, String>("SELECT state FROM analysis_attempts WHERE id=$1")
                    .bind(attempt)
                    .fetch_one(&app.pool)
                    .await?,
                "reserved"
            );
            gateway::settle(&app, attempt, "unknown", None, None).await?;
            gateway::settle(&app, attempt, "unknown", None, None).await?;
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM analysis_attempts WHERE job_id=$1"
                )
                .bind(job)
                .fetch_one(&app.pool)
                .await?,
                1
            );
            assert!(gateway::reserve(&app, job, 0).await?.is_none());
        }
        version += 1;
        services::update(
            &app,
            id,
            &json!({"expected_version":version,"enabled":true}),
            false,
        )
        .await
        .unwrap();
        version += 1;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requiere LARGE_DATABASE_URL aislada; comprueba paginación, no benchmark"]
async fn service_catalog_pages_without_loading_every_service() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("LARGE_DATABASE_URL")?).await?;
    sqlx::migrate!().run(&pool).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "large-catalog-test-only".into(),
            origin: "http://localhost:8080".into(),
            session_id: "large-catalog".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    sqlx::query("WITH inserted AS (INSERT INTO services(id,name) SELECT gen_random_uuid(),'Carga paginada '||lpad(i::text,4,'0') FROM generate_series(1,1001) i RETURNING id,name) INSERT INTO service_revisions(service_id,version,name,description,context,context_hash) SELECT id,1,name,'','','empty' FROM inserted").execute(&app.pool).await?;
    let mut query = std::collections::HashMap::from([
        ("q".into(), "Carga paginada".into()),
        ("limit".into(), "25".into()),
    ]);
    let mut seen = std::collections::HashSet::new();
    let mut pages = 0;
    loop {
        let page = services::list(&app, &query).await.unwrap();
        assert_eq!(page["total_count"], 1001);
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 25);
        for item in items {
            assert!(seen.insert(item["id"].as_str().unwrap().to_owned()));
        }
        pages += 1;
        if let Some(cursor) = page["next_cursor"].as_str() {
            query.insert("cursor".into(), cursor.into());
        } else {
            break;
        }
        assert!(pages <= 41);
    }
    assert_eq!(seen.len(), 1001);
    assert_eq!(pages, 41);
    sqlx::query("WITH inserted AS (INSERT INTO sources(id,logical_name,service_id,config) SELECT gen_random_uuid(),'load-source-'||i,(SELECT id FROM services ORDER BY name LIMIT 1),jsonb_build_object('root_alias','demo-logs','selector','load-'||i||'.log') FROM generate_series(1,1001) i RETURNING id,config) INSERT INTO source_revisions(source_id,version,config) SELECT id,1,config FROM inserted").execute(&app.pool).await?;
    let page = services::all_sources(&app, &std::collections::HashMap::new())
        .await
        .unwrap();
    assert_eq!(page["total_count"], 1001);
    assert_eq!(page["items"].as_array().unwrap().len(), 25);
    assert!(page["next_cursor"].is_string());
    Ok(())
}
