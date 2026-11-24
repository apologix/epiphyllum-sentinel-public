//! Regresión integrada del seguimiento FIX2 de OBS-01:
//! 1) el anti-duplicado de las plantillas de estructura agrupa por el grupo
//!    semántico (servicio + plantilla + raíz + directorio), sin run_id: dos
//!    runs consecutivos del mismo servicio dentro de la ventana producen
//!    una sola incidencia refrescada, anclada al primer run.
//! 2) el diff clasificado persistido (migración 0030) mantiene trazabilidad
//!    captura → overview → contexto del gateway, y los históricos con diff
//!    vacío se sirven recalculados y marcados, sin reinterpretar.
use epiphyllum_sentinel::*;
use serde_json::{Value, json};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

/// La fuente es estable: UN solo file instance para todos sus eventos
/// (el esquema impone UNIQUE(source_id, device, inode, generation); crear
/// uno por evento, como hacía la primera versión de esta fixture, viola
/// esa unicidad y la segunda inserción falla antes de probar nada).
/// Los eventos se distinguen por byte_start dentro del mismo archivo.
async fn insert_event(
    app: &App,
    run: Uuid,
    source_id: Uuid,
    file_id: Uuid,
    service_id: Uuid,
    byte_start: i64,
) -> anyhow::Result<()> {
    let event = Uuid::new_v4();
    sqlx::query("INSERT INTO events(id,run_id,external_event_id,source_id,file_instance_id,generation,byte_start,byte_end,line_hash,event_time,source,event_type,level,service,message,schema_version,service_id) VALUES($1,$2,$1,$3,$4,0,$5,$6,'structure-fixture',now(),'app','app.error','error','fixture','safe evidence',1,$7)")
        .bind(event)
        .bind(run)
        .bind(source_id)
        .bind(file_id)
        .bind(byte_start)
        .bind(byte_start + 1)
        .bind(service_id)
        .execute(&app.pool)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requiere PostgreSQL/pgvector/E5 reales en base aislada"]
async fn structure_group_ignores_run_and_diff_is_traceable() -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    let dir = tempfile::tempdir()?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: dir.path().to_string_lossy().into(),
            embeddings_url: "http://embeddings:8001".into(),
            origin: "http://localhost:8080".into(),
            session_id: "structure-observability-test".into(),
            master_key: None,
            admin_secret: "<redacted>".into(),
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    db::bootstrap(&app).await?;
    let service_id = Uuid::new_v4();
    let source_id = Uuid::new_v4();
    sqlx::query("INSERT INTO services(id,name) VALUES($1,$2)")
        .bind(service_id)
        .bind("structure-test")
        .execute(&app.pool)
        .await?;
    sqlx::query(
        "INSERT INTO sources(id,logical_name,service_id,kind,enabled,config) VALUES($1,$2,$3,'folder',true,$4)",
    )
    .bind(source_id)
    .bind(format!("source-{source_id}"))
    .bind(service_id)
    .bind(json!({"root_alias":"demo-logs","selector":"fixture.ndjson"}))
    .execute(&app.pool)
    .await?;

    // File instance único y estable de la fuente para ambos runs.
    let file_id = Uuid::new_v4();
    sqlx::query("INSERT INTO file_instances(id,source_id,device,inode,prefix_hash,prefix_len,current_path) VALUES($1,$2,1,1,'structure-fixture',0,'fixture.ndjson')")
        .bind(file_id)
        .bind(source_id)
        .execute(&app.pool)
        .await?;

    // Primer run + primera captura: a.txt aparece y abre la incidencia.
    let run1 = Uuid::new_v4();
    sqlx::query("INSERT INTO demo_runs(id) VALUES($1)")
        .bind(run1)
        .execute(&app.pool)
        .await?;
    insert_event(&app, run1, source_id, file_id, service_id, 0).await?;
    std::fs::write(dir.path().join("a.txt"), b"a")?;
    let capture1 = structure::capture(
        &app,
        service_id,
        &json!({"root_alias":"demo-logs","directory":""}),
    )
    .await
    .map_err(|e| anyhow::anyhow!("capture 1: {}", e.1))?;
    let added1 = capture1["diff"]["added"].as_array().unwrap();
    assert!(
        added1
            .iter()
            .any(|n| n["path"] == "a.txt" && n["classification"] == "unexpected_structure_change")
    );
    let incidents = || async {
        sqlx::query(
            "SELECT run_id, deterministic_reason FROM incidents WHERE rule_id='unexpected_structure_change'",
        )
        .fetch_all(&app.pool)
        .await
        .unwrap()
    };
    let rows = incidents().await;
    assert_eq!(rows.len(), 1, "la primera captura abre una incidencia");
    assert_eq!(rows[0].get::<Uuid, _>("run_id"), run1);

    // Segundo run del mismo servicio + segunda captura dentro de la
    // ventana: el grupo es el mismo, así que refresca, no duplica.
    let run2 = Uuid::new_v4();
    sqlx::query("INSERT INTO demo_runs(id) VALUES($1)")
        .bind(run2)
        .execute(&app.pool)
        .await?;
    insert_event(&app, run2, source_id, file_id, service_id, 100).await?;
    std::fs::write(dir.path().join("b.txt"), b"b")?;
    structure::capture(
        &app,
        service_id,
        &json!({"root_alias":"demo-logs","directory":""}),
    )
    .await
    .map_err(|e| anyhow::anyhow!("capture 2: {}", e.1))?;
    let rows = incidents().await;
    assert_eq!(
        rows.len(),
        1,
        "dos runs del mismo servicio y grupo producen una sola incidencia"
    );
    assert_eq!(
        rows[0].get::<Uuid, _>("run_id"),
        run1,
        "el ancla sigue siendo el primer run"
    );
    let reason: Value = rows[0].get("deterministic_reason");
    let merged: Vec<&str> = reason["added_paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str())
        .collect();
    assert!(merged.contains(&"a.txt") && merged.contains(&"b.txt"));
    assert_eq!(reason["accumulated_paths"], 2);

    // Trazabilidad: overview devuelve el diff persistido con clasificación.
    let overview = structure::overview(&app, service_id)
        .await
        .map_err(|e| anyhow::anyhow!("overview: {}", e.1))?;
    let root = overview["roots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["directory"] == "")
        .unwrap()
        .clone();
    assert_eq!(root["diff_source"], "persisted");
    assert!(
        root["diff"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["path"] == "b.txt" && n["classification"] == "unexpected_structure_change")
    );

    // Y el contexto del gateway hereda esa misma clasificación.
    let context = structure::context_for_services(&app, &[service_id]).await;
    assert!(
        context[0]["roots"][0]["diff_added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["path"] == "b.txt" && n["classification"] == "unexpected_structure_change")
    );

    // Compatibilidad histórica: snapshots con diff vacío se sirven
    // recalculados y marcados, sin clasificaciones reinterpretadas.
    for (minutes, nodes) in [
        (60, json!([])),
        (
            30,
            json!([{"path":"old.txt","kind":"file","size":1,"mtime":1,"mode":"0644"}]),
        ),
    ] {
        sqlx::query("INSERT INTO structure_snapshots(id,service_id,root_alias,directory,node_count,truncated,nodes,diff,created_at) VALUES($1,$2,'demo-logs','old',$3,false,$4,'{}',now() - make_interval(mins => $5))")
            .bind(Uuid::new_v4())
            .bind(service_id)
            .bind(nodes.as_array().unwrap().len() as i32)
            .bind(nodes)
            .bind(minutes)
            .execute(&app.pool)
            .await?;
    }
    let overview = structure::overview(&app, service_id)
        .await
        .map_err(|e| anyhow::anyhow!("overview: {}", e.1))?;
    let old = overview["roots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["directory"] == "old")
        .unwrap()
        .clone();
    assert_eq!(old["diff_source"], "recomputed");
    assert!(
        old["diff"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n.get("classification").is_none())
    );
    Ok(())
}
