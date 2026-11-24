use epiphyllum_sentinel::*;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

fn app(pool: sqlx::PgPool) -> App {
    App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-catalog-secret".into(),
            origin: "http://localhost:8080".into(),
            session_id: "service-catalog-test".into(),
            master_key: Some("11".repeat(32)),
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    }
}
fn request(name: &str) -> Value {
    json!({"name":name,"description":"Servicio sintético","context":"Contexto inicial","idempotency_key":Uuid::new_v4()})
}
fn id(v: &Value) -> Uuid {
    v["id"].as_str().unwrap().parse().unwrap()
}
#[tokio::test]
#[ignore = "requiere base PostgreSQL/pgvector aislada sin proveedor"]
async fn catalog_crud_pagination_sources_and_history() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::migrate!().run(&pool).await?;
    let app = app(pool);
    db::bootstrap(&app).await?;
    let payload = request("Nginx principal");
    let a = services::create(&app, &payload).await.unwrap();
    assert_eq!(id(&services::create(&app, &payload).await.unwrap()), id(&a));
    let mut changed = payload.clone();
    changed["context"] = json!("otro");
    assert_eq!(
        services::create(&app, &changed).await.unwrap_err().0,
        axum::http::StatusCode::CONFLICT
    );
    let b = services::create(&app, &request("Aplicación B"))
        .await
        .unwrap();
    let q = HashMap::from([("limit".into(), "1".into())]);
    let first = services::list(&app, &q).await.unwrap();
    assert_eq!(first["total_count"], 2);
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    let mut q2 = q.clone();
    q2.insert(
        "cursor".into(),
        first["next_cursor"].as_str().unwrap().into(),
    );
    let next = services::list(&app, &q2).await.unwrap();
    assert_ne!(first["items"][0]["id"], next["items"][0]["id"]);
    q2.insert("q".into(), "Nginx".into());
    assert!(services::list(&app, &q2).await.is_err());
    let source = json!({"kind":"folder","config":{"root_alias":"demo-logs","selector":"nginx.log"},"enabled":false,"idempotency_key":Uuid::new_v4()});
    let f = services::create_source(&app, id(&a), &source)
        .await
        .unwrap();
    assert_eq!(
        id(&services::create_source(&app, id(&a), &source)
            .await
            .unwrap()),
        id(&f)
    );
    let mut overlapping = source.clone();
    overlapping["idempotency_key"] = json!(Uuid::new_v4());
    overlapping["config"]["selector"] = json!("*.log");
    assert_eq!(
        services::create_source(&app, id(&b), &overlapping)
            .await
            .unwrap_err()
            .0,
        axum::http::StatusCode::CONFLICT
    );
    let mut active_create = source.clone();
    active_create["idempotency_key"] = json!(Uuid::new_v4());
    active_create["enabled"] = json!(true);
    assert!(
        services::create_source(&app, id(&a), &active_create)
            .await
            .is_err()
    );
    let f = services::update_source(
        &app,
        id(&f),
        &json!({"expected_version":f["version"],"enabled":true}),
        false,
    )
    .await
    .unwrap();
    assert_eq!(f["capture_version"], 1);
    let f = services::update_source(
        &app,
        id(&f),
        &json!({"expected_version":f["version"],"enabled":false}),
        false,
    )
    .await
    .unwrap();
    assert_eq!(f["capture_version"], 1);
    let f=services::update_source(&app,id(&f),&json!({"expected_version":f["version"],"config":{"root_alias":"demo-logs","selector":"nginx-new.log"}}),false).await.unwrap();
    assert!(f["capture_version"].as_i64().unwrap() > 1);
    let mcp=services::create_source(&app,id(&a),&json!({"kind":"mcp","config":{"endpoint":"http://mcp-fixture:8090/mcp","resource_uri":"logs://synthetic","synthetic":true},"credential":"synthetic-secret-canary","idempotency_key":Uuid::new_v4()})).await.unwrap();
    assert_eq!(mcp["has_credential"], true);
    assert!(!mcp.to_string().contains("synthetic-secret-canary"));
    assert_eq!(
        services::update_source(
            &app,
            id(&mcp),
            &json!({"expected_version":mcp["version"],"enabled":true}),
            false
        )
        .await
        .unwrap_err()
        .0,
        axum::http::StatusCode::CONFLICT
    );
    let credential = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT ciphertext,nonce FROM source_credentials WHERE source_id=$1",
    )
    .bind(id(&mcp))
    .fetch_one(&app.pool)
    .await?;
    assert_eq!(
        api::decrypt(
            app.config.master_key.as_ref().unwrap(),
            &credential.0,
            &credential.1
        )?,
        "synthetic-secret-canary"
    );
    let renamed = services::update(
        &app,
        id(&a),
        &json!({"expected_version":a["version"],"name":"Nginx renombrado","context":"Nueva guía"}),
        false,
    )
    .await
    .unwrap();
    assert_eq!(id(&renamed), id(&a));
    assert!(
        services::update(
            &app,
            id(&a),
            &json!({"expected_version":a["version"],"name":"Stale"}),
            false
        )
        .await
        .is_err()
    );
    let old: String = sqlx::query_scalar(
        "SELECT context FROM service_revisions WHERE service_id=$1 AND version=1",
    )
    .bind(id(&a))
    .fetch_one(&app.pool)
    .await?;
    assert_eq!(old, "Contexto inicial");
    let deleted = services::update(
        &app,
        id(&a),
        &json!({"expected_version":renamed["version"]}),
        true,
    )
    .await
    .unwrap();
    assert!(!deleted["deleted_at"].is_null());
    assert_eq!(deleted["enabled"], false);
    assert_eq!(
        services::list(&app, &HashMap::new()).await.unwrap()["total_count"],
        1
    );
    assert_eq!(
        services::list(&app, &HashMap::from([("state".into(), "all".into())]))
            .await
            .unwrap()["total_count"],
        2
    );
    let live_sources: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sources WHERE service_id=$1 AND (enabled OR deleted_at IS NULL)",
    )
    .bind(id(&a))
    .fetch_one(&app.pool)
    .await?;
    assert_eq!(live_sources, 0);
    let revisions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM service_revisions WHERE service_id=$1")
            .bind(id(&a))
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(revisions, 3);
    let outbox: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE kind='service.deleted'")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(outbox, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requiere otra base PostgreSQL aislada vacía MIGRATION_DATABASE_URL"]
async fn migration_preserves_mixed_legacy_and_reports_ambiguous_names() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("MIGRATION_DATABASE_URL")?).await?;
    let mut tx = pool.begin().await?;
    for sql in [
        include_str!("../migrations/0001_core.sql"),
        include_str!("../migrations/0002_message_reply.sql"),
        include_str!("../migrations/0003_job_clock.sql"),
        include_str!("../migrations/0004_constraints.sql"),
        include_str!("../migrations/0005_passive_router.sql"),
        include_str!("../migrations/0006_native_formats.sql"),
        include_str!("../migrations/0007_evidence_event_index.sql"),
        include_str!("../migrations/0008_service_names.sql"),
        include_str!("../migrations/0009_record_reviews.sql"),
        include_str!("../migrations/0010_mixed_coverage.sql"),
        include_str!("../migrations/0011_redaction_metadata.sql"),
        include_str!("../migrations/0012_review_revision.sql"),
        include_str!("../migrations/0013_individual_incidents.sql"),
        include_str!("../migrations/0014_chat_workers.sql"),
        include_str!("../migrations/0015_operator_followup.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&mut *tx).await?;
    }
    let source = Uuid::new_v4();
    let run = Uuid::new_v4();
    let file = Uuid::new_v4();
    sqlx::query("INSERT INTO demo_runs(id) VALUES($1)")
        .bind(run)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO sources(id,logical_name) VALUES($1,'demo-logs')")
        .bind(source)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO file_instances(id,source_id,device,inode,prefix_hash,prefix_len,current_path) VALUES($1,$2,1,1,'fixture',0,'mixed.ndjson')").bind(file).bind(source).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO source_cursors VALUES($1,44,44,now())")
        .bind(file)
        .execute(&mut *tx)
        .await?;
    for name in [
        "Nginx",
        "nginx",
        "texto-sin-normalizar",
        "sshd",
        "apache-httpd",
    ] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO text_records(id,run_id,content_hash,byte_length,parser,service,source_id,safe_text) VALUES($1,$2,'fixture',1,'unparsed',$3,$4,'x')").bind(id).bind(run).bind(name).bind(source).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO business_rule_sets VALUES(2,$1)").bind(json!({"rules":[{"id":"R1","service":"sshd","enabled":true,"threshold":7,"window_seconds":60},{"id":"R3","service":"Nginx","enabled":true,"threshold":12,"window_seconds":30},{"id":"R2","enabled":true,"threshold":5,"window_seconds":120}]})).execute(&mut *tx).await?;
    sqlx::raw_sql(include_str!("../migrations/0016_service_catalog.sql"))
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/0017_service_rule_scopes.sql"))
        .execute(&mut *tx)
        .await?;
    let active: Value = sqlx::query_scalar(
        "SELECT definition FROM business_rule_sets ORDER BY version DESC LIMIT 1",
    )
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(active["rules"].as_array().unwrap().len(), 2);
    let scoped = active["rules"][0]["service_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()?;
    let historical: i64 =
        sqlx::query_scalar("SELECT count(*) FROM business_rule_sets WHERE version=2")
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(historical, 1);
    let unresolved: i64 = sqlx::query_scalar("SELECT count(*) FROM unresolved_service_rules")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(unresolved, 1);
    sqlx::query("UPDATE services SET name='SSH renombrado' WHERE id=$1")
        .bind(scoped)
        .execute(&mut *tx)
        .await?;
    let rule_id:String=sqlx::query_scalar("SELECT definition->'rules'->0->>'service_id' FROM business_rule_sets ORDER BY version DESC LIMIT 1").fetch_one(&mut *tx).await?;
    assert_eq!(rule_id, scoped.to_string());

    let associated: i64 =
        sqlx::query_scalar("SELECT count(*) FROM text_records WHERE service_id IS NOT NULL")
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(associated, 2);
    let services: i64 = sqlx::query_scalar("SELECT count(*) FROM services")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(services, 2);
    let cursor: i64 =
        sqlx::query_scalar("SELECT committed_offset FROM source_cursors WHERE file_instance_id=$1")
            .bind(file)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(cursor, 44);
    let legacy: (Option<Uuid>, bool) =
        sqlx::query_as("SELECT service_id,enabled FROM sources WHERE id=$1")
            .bind(source)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(legacy, (None, false));
    let locations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM file_instances WHERE source_id=$1")
            .bind(source)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(locations, 1);
    tx.commit().await?;
    Ok(())
}

async fn http_json(client: &reqwest::Client, base: &str, path: &str, cookie: &str) -> Value {
    let response = client
        .get(format!("{base}/api/v1{path}"))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{path}: {status}: {value}");
    value
}
#[tokio::test]
#[ignore = "requiere base aislada HTTP_DATABASE_URL; servidor HTTP sólo loopback del contenedor"]
async fn protected_http_catalog_and_uuid_filters() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("HTTP_DATABASE_URL")?).await?;
    sqlx::migrate!().run(&pool).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let mut app = app(pool);
    Arc::get_mut(&mut app.config).unwrap().origin = base.clone();
    db::bootstrap(&app).await?;
    let server = tokio::spawn(axum::serve(listener, api::router(app.clone())).into_future());
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{base}/api/v1/services"))
            .send()
            .await?
            .status(),
        401
    );
    let login = client
        .post(format!("{base}/api/v1/session"))
        .header("origin", &base)
        .json(&json!({"secret":"synthetic-catalog-secret"}))
        .send()
        .await?;
    assert_eq!(login.status(), 200);
    let cookie = login.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let session = http_json(&client, &base, "/session", &cookie).await;
    let csrf = session["csrf_token"].as_str().unwrap();
    let create = |path: &str, payload: Value| {
        client
            .post(format!("{base}/api/v1{path}"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .header("x-csrf-token", csrf)
            .json(&payload)
    };
    assert_eq!(
        client
            .post(format!("{base}/api/v1/services"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .json(&request("No CSRF"))
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{base}/api/v1/services"))
            .header("cookie", &cookie)
            .header("origin", "https://hostile.example.test")
            .header("x-csrf-token", csrf)
            .json(&request("Hostile"))
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{base}/api/v1/services/not-a-uuid"))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        400
    );
    assert_eq!(
        client
            .get(format!("{base}/api/v1/services?limit=101"))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        400
    );
    let payload = request("Servicio HTTP <script>inerte</script>");
    let response = create("/services", payload.clone()).send().await?;
    assert_eq!(response.status(), 201);
    let service: Value = response.json().await?;
    let sid = id(&service);
    assert_eq!(
        create("/services", payload)
            .send()
            .await?
            .json::<Value>()
            .await?["id"],
        service["id"]
    );
    let forbidden = json!({"kind":"mcp","idempotency_key":Uuid::new_v4(),"credential":"secret-canary-http","config":{"endpoint":"http://169.254.169.254/mcp","resource_uri":"file:///etc/passwd","synthetic":true}});
    assert_eq!(
        create(&format!("/services/{sid}/sources"), forbidden)
            .send()
            .await?
            .status(),
        400
    );
    let source=create(&format!("/services/{sid}/sources"),json!({"kind":"folder","idempotency_key":Uuid::new_v4(),"config":{"root_alias":"demo-logs","selector":"http.ndjson"},"analysis":{"system":"Nginx","protocol":"HTTP","adapter":"sentinel-json","context":"Solo solicitudes observadas","rules":[{"id":"R3","enabled":true,"threshold":1,"window_seconds":30,"condition":{"field":"level","operator":"eq","value":"error"}}]}})).send().await?;
    assert_eq!(source.status(), 201);
    // Real persistent evidence, attributed to the configured service, independent of declared log name.
    let source: Value = source.json().await?;
    let source_id = id(&source);
    assert_eq!(source["analysis"]["protocol"], "HTTP");
    let mcp_source=create(&format!("/services/{sid}/sources"),json!({"kind":"mcp","idempotency_key":Uuid::new_v4(),"config":{"endpoint":"http://mcp-fixture:8090/mcp","resource_uri":"logs://synthetic/nginx","synthetic":true}})).send().await?;
    assert_eq!(mcp_source.status(), 201);
    let mcp_source: Value = mcp_source.json().await?;
    let checked = create(&format!("/sources/{}/check", id(&mcp_source)), json!({}))
        .send()
        .await?;
    assert_eq!(checked.status(), 200);
    let checked: Value = checked.json().await?;
    assert_eq!(checked["readable"], true);
    assert_eq!(checked["connection_attempted"], true);
    assert_eq!(checked["continuity"], "immutable_snapshot");
    services::update_source(
        &app,
        id(&mcp_source),
        &json!({"expected_version":mcp_source["version"],"enabled":true}),
        false,
    )
    .await
    .unwrap();
    let run = Uuid::new_v4();
    let file = Uuid::new_v4();
    let event = Uuid::new_v4();
    let incident = Uuid::new_v4();
    sqlx::query("INSERT INTO demo_runs(id) VALUES($1)")
        .bind(run)
        .execute(&app.pool)
        .await?;
    sqlx::query("INSERT INTO file_instances(id,source_id,device,inode,prefix_hash,prefix_len,current_path) VALUES($1,$2,1,1,'http-fixture',0,'http.ndjson')").bind(file).bind(source_id).execute(&app.pool).await?;
    sqlx::query("INSERT INTO events(id,run_id,external_event_id,source_id,file_instance_id,generation,byte_start,byte_end,line_hash,event_time,source,event_type,level,service,message,schema_version,service_id) VALUES($1,$2,$1,$3,$4,0,0,1,'http-fixture',now(),'app','app.error','error','DECLARED WRONG','safe evidence',1,$5)").bind(event).bind(run).bind(source_id).bind(file).bind(sid).execute(&app.pool).await?;
    sqlx::query("INSERT INTO text_records(id,run_id,event_id,content_hash,byte_length,parser,service,source_id,safe_text,service_id) VALUES($1,$2,$1,'http-fixture',1,'sentinel-json','DECLARED WRONG',$3,'safe evidence',$4)").bind(event).bind(run).bind(source_id).bind(sid).execute(&app.pool).await?;
    let recorded_version: Option<i32> =
        sqlx::query_scalar("SELECT source_version FROM text_records WHERE id=$1")
            .bind(event)
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(recorded_version, Some(1));
    let preview: Value = create(&format!("/sources/{source_id}/rules/preview"), json!({}))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(preview["rules"][0]["match_count"], 1);
    assert_eq!(preview["rules"][0]["matches"][0]["event_id"], json!(event));
    let updated=services::update_source(&app,source_id,&json!({"expected_version":source["version"],"analysis":{"system":"Nginx","protocol":"HTTP","adapter":"sentinel-json","context":"Contexto actualizado","rules":[]}}),false).await.unwrap();
    let old_context: String = sqlx::query_scalar(
        "SELECT analysis->>'context' FROM source_revisions WHERE source_id=$1 AND version=1",
    )
    .bind(source_id)
    .fetch_one(&app.pool)
    .await?;
    assert_eq!(old_context, "Solo solicitudes observadas");
    let preview_after: Value = create(&format!("/sources/{source_id}/rules/preview"), json!({}))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(preview_after["rules"], json!([]));
    let history = http_json(
        &client,
        &base,
        &format!("/sources/{source_id}/revisions?limit=20"),
        &cookie,
    )
    .await;
    assert_eq!(history["items"].as_array().unwrap().len(), 2);
    let restored: Value = create(
        &format!("/sources/{source_id}/restore"),
        json!({"expected_version":updated["version"],"restore_version":1}),
    )
    .send()
    .await?
    .json()
    .await?;
    assert_eq!(
        restored["analysis"]["context"],
        "Solo solicitudes observadas"
    );
    assert_eq!(restored["version"], 3);
    sqlx::query("INSERT INTO incidents(id,incident_key,run_id,rule_id,rule_version,group_key,severity,title,opened_at,last_match_at,deterministic_reason) VALUES($1,$2,$3,'R3',1,$4,'medium','HTTP fixture',now(),now(),'{}')").bind(incident).bind(format!("http-{incident}")).bind(run).bind(json!({"service":"DECLARED WRONG"})).execute(&app.pool).await?;
    sqlx::query("INSERT INTO incident_events(incident_id,event_id) VALUES($1,$2)")
        .bind(incident)
        .bind(event)
        .execute(&app.pool)
        .await?;
    sqlx::query("INSERT INTO incident_services VALUES($1,$2)")
        .bind(incident)
        .bind(sid)
        .execute(&app.pool)
        .await?;
    for path in [
        format!("/reports?service_id={sid}"),
        format!("/events?service_id={sid}"),
        format!("/records?service_id={sid}"),
    ] {
        let page = http_json(&client, &base, &path, &cookie).await;
        assert_eq!(page["items"].as_array().unwrap().len(), 1, "{path}");
        assert_eq!(page["items"][0]["service"], service["name"]);
    }
    let report = http_json(&client, &base, &format!("/reports/{incident}"), &cookie).await;
    assert_eq!(report["services"][0]["id"], service["id"]);
    http_json(
        &client,
        &base,
        &format!("/coverage?service_id={sid}"),
        &cookie,
    )
    .await;
    let nobody = Uuid::new_v4();
    for path in ["reports", "events", "records"] {
        assert_eq!(
            http_json(
                &client,
                &base,
                &format!("/{path}?service_id={nobody}"),
                &cookie
            )
            .await["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
    assert_eq!(
        client
            .get(format!("{base}/api/v1/coverage?service_id=bad"))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        400
    );
    let update = |path: &str, payload: Value| {
        client
            .put(format!("{base}/api/v1{path}"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .header("x-csrf-token", csrf)
            .json(&payload)
    };
    let conversation = Uuid::new_v4();
    let message = Uuid::new_v4();
    let job = Uuid::new_v4();
    sqlx::query("INSERT INTO conversations(id,incident_id) VALUES($1,$2)")
        .bind(conversation)
        .bind(incident)
        .execute(&app.pool)
        .await?;
    sqlx::query("INSERT INTO messages(id,conversation_id,ordinal,role,content,state,evidence_version,request_id,payload_hash) VALUES($1,$2,1,'user','{}','pending',1,$3,'fixture')").bind(message).bind(conversation).bind(Uuid::new_v4()).execute(&app.pool).await?;
    sqlx::query("INSERT INTO analysis_jobs(id,kind,incident_id,message_id,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'chat',$2,$3,1,1,'mock','mock-v1','fixture','{}','pending')").bind(job).bind(incident).bind(message).execute(&app.pool).await?;
    sqlx::query("INSERT INTO job_services VALUES($1,$2,1)")
        .bind(job)
        .bind(sid)
        .execute(&app.pool)
        .await?;
    assert_eq!(
        update(
            &format!("/services/{sid}"),
            json!({"expected_version":1,"enabled":false})
        )
        .send()
        .await?
        .status(),
        200
    );
    let message_state: String = sqlx::query_scalar("SELECT state FROM messages WHERE id=$1")
        .bind(message)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(message_state, "blocked_config");
    assert_eq!(
        update(
            &format!("/services/{sid}"),
            json!({"expected_version":2,"enabled":true})
        )
        .send()
        .await?
        .status(),
        200
    );
    let message_state: String = sqlx::query_scalar("SELECT state FROM messages WHERE id=$1")
        .bind(message)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(message_state, "pending");
    let changed = update(
        &format!("/services/{sid}"),
        json!({"expected_version":3,"name":"Nombre actualizado"}),
    )
    .send()
    .await?;
    assert_eq!(changed.status(), 200);
    assert_eq!(
        update(
            &format!("/services/{sid}"),
            json!({"expected_version":1,"name":"Conflicto"})
        )
        .send()
        .await?
        .status(),
        409
    );
    let report = http_json(&client, &base, &format!("/reports/{incident}"), &cookie).await;
    assert_eq!(report["service"], "Nombre actualizado");
    let deleted = client
        .delete(format!("{base}/api/v1/services/{sid}"))
        .header("cookie", &cookie)
        .header("origin", &base)
        .header("x-csrf-token", csrf)
        .json(&json!({"expected_version":4}))
        .send()
        .await?;
    assert_eq!(deleted.status(), 200);
    let message_state: String = sqlx::query_scalar("SELECT state FROM messages WHERE id=$1")
        .bind(message)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(message_state, "superseded");
    assert!(
        !http_json(&client, &base, &format!("/services/{sid}"), &cookie).await["deleted_at"]
            .is_null()
    );
    assert_eq!(
        http_json(
            &client,
            &base,
            &format!("/reports?service_id={sid}"),
            &cookie
        )
        .await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        http_json(&client, &base, "/services?state=all", &cookie).await["total_count"],
        1
    );
    server.abort();
    Ok(())
}
