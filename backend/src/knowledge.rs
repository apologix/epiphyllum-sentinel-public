use crate::contracts::{Policy, validate_policy};
use crate::*;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
pub async fn embed(app: &App, texts: &[String], kind: &str) -> anyhow::Result<Vec<Vec<f32>>> {
    let res = app
        .client
        .post(format!("{}/embed", app.config.embeddings_url))
        .json(&json!({"texts":texts,"kind":kind}))
        .send()
        .await?;
    anyhow::ensure!(res.status().is_success(), "embeddings_unavailable");
    anyhow::ensure!(
        res.content_length().unwrap_or(0) <= 131072,
        "embeddings_response_limit"
    );
    let b = res.bytes().await?;
    anyhow::ensure!(b.len() <= 131072, "embeddings_response_limit");
    let v: Value = serde_json::from_slice(&b)?;
    anyhow::ensure!(
        v["model_revision"] == MODEL_REV && v["dimension"] == 384,
        "embedding_revision_mismatch"
    );
    let vectors: Vec<Vec<f32>> = serde_json::from_value(v["vectors"].clone())?;
    anyhow::ensure!(vectors.len() == texts.len(), "vector_count");
    for vec in &vectors {
        let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        anyhow::ensure!(
            vec.len() == 384 && vec.iter().all(|x| x.is_finite()) && (norm - 1.0).abs() < 0.01,
            "invalid_vector"
        );
    }
    Ok(vectors)
}
pub fn vector_literal(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub async fn seed(app: &App) -> anyhow::Result<()> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM knowledge_documents")
        .fetch_one(&app.pool)
        .await?;
    let seeds: Value = serde_json::from_str(include_str!("../../corpus/seed.json"))?;
    let mut tx = app.pool.begin().await?;
    for (i, d) in seeds.as_array().unwrap().iter().enumerate() {
        let id = Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("sentinel-knowledge-{i}").as_bytes(),
        );
        sqlx::query("INSERT INTO knowledge_documents(id,title,kind,source,license) VALUES($1,$2,$3,$4,'CC0-1.0') ON CONFLICT DO NOTHING").bind(id).bind(d["title"].as_str()).bind(d["kind"].as_str()).bind(d["source"].as_str().unwrap_or("Corpus educativo original de Epiphyllum Sentinel, datos ficticios")).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO knowledge_revisions(document_id,revision,text,hash,metadata) VALUES($1,1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(id).bind(d["text"].as_str()).bind(hash(d["text"].as_str().unwrap())).bind(json!({"policy":d["policy"]})).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    // Existing installations retain their active version; new seeds remain drafts until activation.
    if n > 0 {
        return Ok(());
    }
    let manifest:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('document_id',document_id,'revision',revision) FROM knowledge_revisions ORDER BY document_id").fetch_all(&app.pool).await?;
    create_build(
        app,
        &json!(manifest),
        Uuid::new_v5(&Uuid::NAMESPACE_OID, b"sentinel-seed-build"),
    )
    .await?;
    Ok(())
}
pub async fn create_build(app: &App, manifest: &Value, key: Uuid) -> anyhow::Result<Uuid> {
    let a = manifest
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("manifest_invalid"))?;
    anyhow::ensure!(!a.is_empty() && a.len() <= 200, "document_limit");
    let h = hash(manifest.to_string());
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(4141)")
        .execute(&mut *tx)
        .await?;
    if let Some(r) =
        sqlx::query("SELECT id,manifest_hash FROM corpus_versions WHERE idempotency_key=$1")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
    {
        anyhow::ensure!(
            r.get::<String, _>("manifest_hash") == h,
            "idempotency_conflict"
        );
        return Ok(r.get("id"));
    }
    let ongoing: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM corpus_versions WHERE state='building')")
            .fetch_one(&mut *tx)
            .await?;
    anyhow::ensure!(!ongoing, "build_in_progress");
    let mut policies = Vec::new();
    let mut total = 0;
    let mut seen = std::collections::HashSet::new();
    let mut members = Vec::new();
    for m in a {
        anyhow::ensure!(
            m.as_object().is_some_and(|o| o.len() == 2
                && o.contains_key("document_id")
                && o.contains_key("revision")),
            "manifest_schema"
        );
        anyhow::ensure!(
            m["revision"]
                .as_i64()
                .is_some_and(|r| (1..=1000000).contains(&r)),
            "revision_invalid"
        );
        let id: Uuid = serde_json::from_value(m["document_id"].clone())?;
        let revision = m["revision"]
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("revision_invalid"))? as i32;
        anyhow::ensure!(seen.insert(id), "duplicate_document");
        let r=sqlx::query("SELECT r.text,r.metadata,d.kind FROM knowledge_revisions r JOIN knowledge_documents d ON d.id=r.document_id WHERE document_id=$1 AND revision=$2").bind(id).bind(revision).fetch_one(&mut *tx).await?;
        total += r.get::<String, _>("text").len();
        if r.get::<String, _>("kind") == "decision_rule" {
            let meta: Value = r.get("metadata");
            let p: Policy = serde_json::from_value(meta["policy"].clone())?;
            validate_policy(&p)?;
            policies.push(json!({"id":id,"revision":revision,"definition":p}));
        }
        members.push((id, revision));
    }
    anyhow::ensure!(
        total <= 4194304 && !policies.is_empty(),
        "corpus_or_policy_invalid"
    );
    let policy_id = Uuid::new_v4();
    let id = Uuid::new_v4();
    let ps = json!(policies);
    sqlx::query("INSERT INTO policy_sets(id,policies,hash) VALUES($1,$2,$3)")
        .bind(policy_id)
        .bind(&ps)
        .bind(hash(ps.to_string()))
        .execute(&mut *tx)
        .await?;
    for p in &policies {
        sqlx::query("INSERT INTO decision_policies(id,revision,document_id,scope,definition) VALUES($1,$2,$1,'analysis/chat',$3) ON CONFLICT DO NOTHING").bind(serde_json::from_value::<Uuid>(p["id"].clone())?).bind(p["revision"].as_i64().unwrap() as i32).bind(&p["definition"]).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO corpus_versions(id,policy_set_id,embedding_model_revision,dimension,state,idempotency_key,manifest_hash) VALUES($1,$2,$3,384,'building',$4,$5)").bind(id).bind(policy_id).bind(MODEL_REV).bind(key).bind(h).execute(&mut *tx).await?;
    for (doc, rev) in members {
        sqlx::query("INSERT INTO corpus_members VALUES($1,$2,$3)")
            .bind(id)
            .bind(doc)
            .bind(rev)
            .execute(&mut *tx)
            .await?;
    }
    db::emit(&mut tx, "knowledge.build.updated", id, 1).await?;
    tx.commit().await?;
    Ok(id)
}
pub async fn build_pending(app: &App) -> anyhow::Result<()> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM corpus_versions WHERE state='building' ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&app.pool)
    .await?;
    let Some(id) = id else {
        return Ok(());
    };
    // Offline dependency outages leave the durable build resumable.
    if app
        .client
        .get(format!("{}/health", app.config.embeddings_url))
        .send()
        .await
        .is_err()
    {
        return Ok(());
    }
    match build(app, id).await {
        Ok(()) => (),
        Err(e) => {
            tracing::warn!(code = "knowledge_build_failed");
            let _ = e;
            sqlx::query(
                "UPDATE corpus_versions SET state='failed',reason='indexing_failed' WHERE id=$1",
            )
            .bind(id)
            .execute(&app.pool)
            .await?;
        }
    }
    Ok(())
}
async fn build(app: &App, id: Uuid) -> anyhow::Result<()> {
    let members=sqlx::query("SELECT r.* FROM corpus_members m JOIN knowledge_revisions r ON r.document_id=m.document_id AND r.revision=m.revision WHERE m.corpus_id=$1 ORDER BY m.document_id").bind(id).fetch_all(&app.pool).await?;
    let mut count = 0;
    for m in members {
        let doc: Uuid = m.get("document_id");
        let rev: i32 = m.get("revision");
        let text: String = m.get("text");
        let res = app
            .client
            .post(format!("{}/chunks", app.config.embeddings_url))
            .json(&json!({"text":text}))
            .send()
            .await?
            .error_for_status()?;
        let b = res.bytes().await?;
        anyhow::ensure!(b.len() <= 262144, "chunks_too_large");
        let parts: Value = serde_json::from_slice(&b)?;
        anyhow::ensure!(parts["model_revision"] == MODEL_REV, "model_mismatch");
        for (ordinal, c) in parts["chunks"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("chunks_invalid"))?
            .iter()
            .enumerate()
        {
            count += 1;
            anyhow::ensure!(count <= 2000, "chunk_limit");
            let ct = c["text"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("chunk_text"))?;
            let tokens = c["token_count"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("chunk_tokens"))?;
            anyhow::ensure!(tokens <= 400 && !ct.is_empty(), "chunk_invalid");
            let cid = Uuid::new_v5(&doc, format!("{rev}:{ordinal}").as_bytes());
            sqlx::query("INSERT INTO knowledge_chunks(id,document_id,revision,ordinal,text,hash,token_count) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING").bind(cid).bind(doc).bind(rev).bind(ordinal as i32).bind(ct).bind(hash(ct)).bind(tokens as i32).execute(&app.pool).await?;
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM knowledge_embeddings WHERE corpus_id=$1 AND chunk_id=$2)").bind(id).bind(cid).fetch_one(&app.pool).await?;
            if !exists {
                let cached:Option<String>=sqlx::query_scalar("SELECT e.embedding::text FROM knowledge_embeddings e JOIN knowledge_chunks c ON c.id=e.chunk_id WHERE c.hash=$1 AND e.model_revision=$2 LIMIT 1").bind(hash(ct)).bind(MODEL_REV).fetch_optional(&app.pool).await?;
                let v = if let Some(v) = cached {
                    v
                } else {
                    vector_literal(&embed(app, &[ct.to_owned()], "passage").await?[0])
                };
                sqlx::query("INSERT INTO knowledge_embeddings(corpus_id,chunk_id,embedding,model_revision) VALUES($1,$2,$3::vector,$4) ON CONFLICT DO NOTHING").bind(id).bind(cid).bind(v).bind(MODEL_REV).execute(&app.pool).await?;
            }
            if std::env::var("SENTINEL_FAILPOINT").as_deref() == Ok("indexing_after_chunk") {
                std::process::abort();
            }
        }
        sqlx::query(
            "UPDATE knowledge_revisions SET state='ready' WHERE document_id=$1 AND revision=$2",
        )
        .bind(doc)
        .bind(rev)
        .execute(&app.pool)
        .await?;
    }
    let mut tx = app.pool.begin().await?;
    sqlx::query("UPDATE corpus_versions SET state='ready',reason=NULL WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Only bootstrap activates automatically; all later versions require explicit CAS.
    sqlx::query("INSERT INTO knowledge_state(singleton,active_corpus_id,active_policy_version) SELECT true,id,policy_set_id FROM corpus_versions WHERE id=$1 ON CONFLICT DO NOTHING").bind(id).execute(&mut *tx).await?;
    db::emit(&mut tx, "knowledge.build.updated", id, 2).await?;
    tx.commit().await?;
    Ok(())
}
/// Recuperación con ámbito (CON-01/OBS-01): los documentos específicos de
/// los servicios involucrados tienen prioridad cuando son pertinentes (hasta
/// la mitad de los huecos), sin excluir las guías generales. Cada fragmento
/// declara su ámbito (`scope`: service|general) para el snapshot y la UI.
/// La similitud nunca concede permisos: solo ordena contexto.
pub async fn retrieve(
    app: &App,
    corpus: Uuid,
    query: &str,
    service_ids: &[Uuid],
) -> anyhow::Result<Value> {
    let revision: String = sqlx::query_scalar(
        "SELECT embedding_model_revision FROM corpus_versions WHERE id=$1 AND state='ready'",
    )
    .bind(corpus)
    .fetch_one(&app.pool)
    .await?;
    anyhow::ensure!(revision == MODEL_REV, "model_revision_mismatch");
    let v = vector_literal(&embed(app, &[query.to_owned()], "query").await?[0]);
    // Candidatos generales y específicos por separado (corrección
    // REVIEW-OBS-01, P2): un único top global previo perdía fragmentos del
    // servicio antes de poder priorizarlos. Se fusionan deduplicados y
    // recién después se aplican umbral, límite y presupuesto.
    const CANDIDATE_SQL: &str = "SELECT jsonb_build_object('chunk_id',c.id,'document_id',c.document_id,'revision',c.revision,'text',c.text,'title',d.title,'source',d.source,'service_id',d.service_id,'scope',CASE WHEN d.service_id IS NULL THEN 'general' ELSE 'service' END,'distance',e.embedding <=> $2::vector) FROM knowledge_embeddings e JOIN knowledge_chunks c ON c.id=e.chunk_id JOIN knowledge_documents d ON d.id=c.document_id WHERE e.corpus_id=$1 AND d.kind <> 'decision_rule'";
    let general: Vec<Value> = sqlx::query_scalar(&format!(
        "{CANDIDATE_SQL} AND d.service_id IS NULL ORDER BY e.embedding <=> $2::vector,c.id LIMIT 8"
    ))
    .bind(corpus)
    .bind(v.clone())
    .fetch_all(&app.pool)
    .await?;
    let specific: Vec<Value> = if service_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar(&format!(
            "{CANDIDATE_SQL} AND d.service_id = ANY($3) ORDER BY e.embedding <=> $2::vector,c.id LIMIT 8"
        ))
        .bind(corpus)
        .bind(v.clone())
        .bind(service_ids)
        .fetch_all(&app.pool)
        .await?
    };
    let chunks = prioritize_service_scope(merge_candidates(general, specific), service_ids, 4);

    // Calibrated threshold is versioned in corpus/rag-calibration.json, verified by the evaluation suite.
    let calibration: Value =
        serde_json::from_str(include_str!("../../corpus/rag-calibration.json"))?;
    let threshold = calibration["max_distance"].as_f64().unwrap();
    let mut selected = Vec::new();
    let mut bytes = 0;
    for c in chunks {
        if c["distance"].as_f64().unwrap_or(2.0) > threshold {
            continue;
        }
        let len = c.to_string().len();
        if bytes + len <= 4096 {
            bytes += len;
            selected.push(c);
        }
    }
    Ok(json!(selected))
}

/// Fusiona candidatos generales y específicos deduplicando por chunk_id y
/// ordenando por distancia. Función pura: la prioridad de ámbito se aplica
/// después, sobre el conjunto completo.
pub fn merge_candidates(general: Vec<Value>, specific: Vec<Value>) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut merged: Vec<Value> = Vec::new();
    for c in general.into_iter().chain(specific) {
        if seen.insert(c["chunk_id"].as_str().unwrap_or("").to_string()) {
            merged.push(c);
        }
    }
    merged.sort_by(|a, b| {
        a["distance"]
            .as_f64()
            .unwrap_or(2.0)
            .partial_cmp(&b["distance"].as_f64().unwrap_or(2.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    merged
}

/// Selección con prioridad de ámbito: de los candidatos por distancia, se
/// reservan hasta `service_slots` huecos para documentos del servicio (si
/// superan el mismo umbral que luego aplica retrieve) y el resto se rellena
/// por distancia global. Función pura para poder probarla sin base.
pub fn prioritize_service_scope(
    chunks: Vec<Value>,
    service_ids: &[Uuid],
    limit: usize,
) -> Vec<Value> {
    if service_ids.is_empty() {
        return chunks.into_iter().take(limit).collect();
    }
    let service_slots = limit / 2;
    let mut selected: Vec<Value> = Vec::new();
    let mut rest: Vec<Value> = Vec::new();
    for c in chunks {
        let is_service = c["service_id"]
            .as_str()
            .and_then(|x| x.parse::<Uuid>().ok())
            .is_some_and(|id| service_ids.contains(&id));
        if is_service && selected.len() < service_slots {
            selected.push(c);
        } else {
            rest.push(c);
        }
    }
    for c in rest {
        if selected.len() >= limit {
            break;
        }
        if !selected.iter().any(|x| x["chunk_id"] == c["chunk_id"]) {
            selected.push(c);
        }
    }
    selected
}
#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn service_doc_outside_global_top_enters_via_service_query() {
        // El top global (8) no contiene el documento del servicio; la
        // consulta específica lo aporta y la fusión + prioridad lo incluyen.
        let sid = Uuid::new_v4();
        let mk = |id: &str, svc: Option<Uuid>, d: f64| json!({"chunk_id":id,"service_id":svc.map(|x| x.to_string()),"distance":d});
        let general: Vec<Value> = (0..8)
            .map(|i| mk(&format!("g{i}"), None, 0.10 + i as f64 * 0.01))
            .collect();
        let specific = vec![mk("s-doc", Some(sid), 0.30)];
        let merged = merge_candidates(general, specific);
        assert_eq!(merged.len(), 9);
        let out = prioritize_service_scope(merged, &[sid], 4);
        assert!(out.iter().any(|c| c["chunk_id"] == "s-doc"));
        assert!(out.iter().any(|c| c["chunk_id"] == "g0"));
        // Deduplicación por chunk_id
        let dup = merge_candidates(vec![mk("x", None, 0.1)], vec![mk("x", None, 0.2)]);
        assert_eq!(dup.len(), 1);
    }
    #[test]
    fn service_scope_gets_priority_without_excluding_general() {
        let sid = Uuid::new_v4();
        let mk = |id: &str, svc: Option<Uuid>| json!({"chunk_id":id,"service_id":svc.map(|x| x.to_string()),"distance":0.1});
        let chunks = vec![
            mk("g1", None),
            mk("g2", None),
            mk("s1", Some(sid)),
            mk("g3", None),
        ];
        let out = prioritize_service_scope(chunks.clone(), &[sid], 4);
        assert_eq!(out.len(), 4);
        assert!(out.iter().any(|c| c["chunk_id"] == "s1"));
        let out = prioritize_service_scope(chunks, &[], 2);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["chunk_id"], "g1");
    }
}
#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[tokio::test]
    async fn rejects_forged_embedding_contracts() {
        for v in [
            json!({"model_revision":"foreign","dimension":384,"vectors":[]}),
            json!({"model_revision":MODEL_REV,"dimension":383,"vectors":[vec![1.0;383]]}),
            json!({"model_revision":MODEL_REV,"dimension":384,"vectors":[vec![0.0;384]]}),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let router = axum::Router::new().route(
                "/embed",
                axum::routing::post(move || {
                    let v = v.clone();
                    async move { axum::Json(v) }
                }),
            );
            let h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let app = App {
                pool: sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://unused@127.0.0.1/unused")
                    .unwrap(),
                client: reqwest::Client::new(),
                config: std::sync::Arc::new(Config {
                    log_root: "unused".into(),
                    embeddings_url: format!("http://{addr}"),
                    admin_secret: "unused".into(),
                    origin: "unused".into(),
                    session_id: "test".into(),
                    master_key: None,
                }),
                volatile_key: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
                authorization: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
                leadership: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            };
            assert!(
                embed(&app, &["consulta ficticia".to_string()], "query")
                    .await
                    .is_err()
            );
            h.abort();
        }
    }
}
