use epiphyllum_sentinel::*;
use std::sync::Arc;
use uuid::Uuid;
#[tokio::test]
#[ignore = "requiere base aislada sentinel_real_egress; nunca realiza peticiones externas"]
async fn real_record_reserves_external_provider() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    anyhow::ensure!(
        url.ends_with("/sentinel_real_egress"),
        "isolated_database_required"
    );
    let pool = sqlx::PgPool::connect(&url).await?;
    sqlx::migrate!().run(&pool).await?;
    let app = App {
        pool,
        client: reqwest::Client::new(),
        config: Arc::new(Config {
            log_root: "/data/logs".into(),
            embeddings_url: "http://embeddings:8001".into(),
            admin_secret: "synthetic-egress-check".into(),
            origin: "http://localhost:8080".into(),
            session_id: "egress-check".into(),
            master_key: None,
        }),
        volatile_key: Arc::new(tokio::sync::Mutex::new(None)),
        authorization: Arc::new(tokio::sync::Mutex::new(None)),
        leadership: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    // Crea las cuentas de presupuesto que reserve() bloquea con FOR UPDATE.
    db::bootstrap(&app).await?;
    let (service, source, run, record, job, segment) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    sqlx::query("INSERT INTO services(id,name) VALUES($1,'Prueba real simulada')")
        .bind(service)
        .execute(&app.pool)
        .await?;
    sqlx::query("INSERT INTO sources(id,logical_name,service_id,kind,enabled,data_class,config) VALUES($1,$2,$3,'folder',true,'real','{}')").bind(source).bind(source.to_string()).bind(service).execute(&app.pool).await?;
    sqlx::query("INSERT INTO demo_runs(id) VALUES($1)")
        .bind(run)
        .execute(&app.pool)
        .await?;
    sqlx::query("INSERT INTO text_records(id,run_id,content_hash,byte_length,parser,service,source_id,service_id,data_class) VALUES($1,$2,'test',2,'unparsed','Prueba real simulada',$3,$4,'real')").bind(record).bind(run).bind(source).bind(service).execute(&app.pool).await?;
    sqlx::query("INSERT INTO analysis_jobs(id,kind,evidence_version,provider_profile_version,provider,model,snapshot_hash,snapshot,state) VALUES($1,'review',1,1,'openai','synthetic-model','','{}','pending')").bind(job).execute(&app.pool).await?;
    sqlx::query("INSERT INTO review_segments(id,record_id,ordinal,byte_start,byte_end,content,content_hash,job_id) VALUES($1,$2,0,0,2,'ok','test',$3)").bind(segment).bind(record).bind(job).execute(&app.pool).await?;
    // Se retiró el permiso acotado de datos reales: un registro real ya puede
    // reservar y enviar. Se comprueba que la reserva ocurre de verdad.
    let attempt = gateway::reserve(&app, job, 0)
        .await?
        .expect("un registro real ya no debe bloquearse por egress");
    let state: String = sqlx::query_scalar("SELECT state FROM analysis_jobs WHERE id=$1")
        .bind(job)
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(state, "reserved");
    let attempts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis_attempts WHERE id=$1")
            .bind(attempt)
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(attempts, 1);
    Ok(())
}
