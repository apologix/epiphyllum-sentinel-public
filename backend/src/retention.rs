use crate::*;
pub async fn prune(app: &App) -> anyhow::Result<()> {
    let mut tx = app.pool.begin().await?;
    sqlx::query("DELETE FROM outbox_events WHERE created_at<now()-interval '24 hours'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM ingestion_errors WHERE observed_at<now()-interval '7 days'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM admin_requests WHERE created_at<now()-interval '1 day'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM admin_sessions WHERE expires_at<now()")
        .execute(&mut *tx)
        .await?;
    // Reports, conversations and all referenced snapshots/ledger survive until explicit removal.
    sqlx::query("DELETE FROM detection_work WHERE state='done' AND event_id IN(SELECT id FROM events e WHERE ingested_at<now()-interval '7 days' AND NOT EXISTS(SELECT 1 FROM incident_events WHERE event_id=e.id) AND NOT EXISTS(SELECT 1 FROM text_records WHERE event_id=e.id))").execute(&mut *tx).await?;
    sqlx::query("DELETE FROM events e WHERE ingested_at<now()-interval '7 days' AND NOT EXISTS(SELECT 1 FROM incident_events WHERE event_id=e.id) AND NOT EXISTS(SELECT 1 FROM text_records WHERE event_id=e.id) AND NOT EXISTS(SELECT 1 FROM detection_work WHERE event_id=e.id)").execute(&mut *tx).await?;
    // Only completed clear real records with no incident or finding may expire.
    // Pending, failed, ambiguous and cited evidence retain their original contents.
    sqlx::query("SELECT pg_advisory_xact_lock(7616)")
        .execute(&mut *tx)
        .await?;
    let expired:Vec<uuid::Uuid> = sqlx::query_scalar("SELECT r.id FROM text_records r WHERE r.data_class='real' AND r.content_expired_at IS NULL AND r.received_at < now()-interval '7 days' AND EXISTS(SELECT 1 FROM review_segments s WHERE s.record_id=r.id) AND NOT EXISTS(SELECT 1 FROM incident_events ie WHERE ie.event_id=r.event_id) AND NOT EXISTS(SELECT 1 FROM record_incidents ri WHERE ri.record_id=r.id) AND NOT EXISTS(SELECT 1 FROM review_segments s JOIN finding_segments f ON f.segment_id=s.id WHERE s.record_id=r.id) AND NOT EXISTS(SELECT 1 FROM review_segments s LEFT JOIN analysis_jobs j ON j.id=s.job_id LEFT JOIN analyses a ON a.job_id=j.id WHERE s.record_id=r.id AND (s.disposition IS DISTINCT FROM 'clear' OR j.state NOT IN('succeeded','cached') OR a.created_at IS NULL OR a.created_at>=now()-interval '7 days')) FOR UPDATE OF r SKIP LOCKED LIMIT 200")
        .fetch_all(&mut *tx).await?;
    if !expired.is_empty() {
        sqlx::query("UPDATE analysis_jobs j SET snapshot=jsonb_build_object('schema_version',j.snapshot->'schema_version','kind','review','content_expired',true,'original_snapshot_hash',j.snapshot_hash), snapshot_expired_at=now() WHERE j.kind='review' AND j.snapshot_expired_at IS NULL AND EXISTS(SELECT 1 FROM review_segments s WHERE s.job_id=j.id AND s.record_id=ANY($1)) AND NOT EXISTS(SELECT 1 FROM review_segments s WHERE s.job_id=j.id AND NOT (s.record_id=ANY($1))) AND NOT EXISTS(SELECT 1 FROM review_findings f WHERE f.job_id=j.id)")
            .bind(&expired).execute(&mut *tx).await?;
        sqlx::query("UPDATE retrieval_snapshots k SET query='[contenido temporal eliminado]' FROM analysis_jobs j WHERE j.id=k.job_id AND j.snapshot_expired_at IS NOT NULL AND EXISTS(SELECT 1 FROM review_segments s WHERE s.job_id=j.id AND s.record_id=ANY($1))")
            .bind(&expired).execute(&mut *tx).await?;
        sqlx::query("UPDATE review_segments SET content='' WHERE record_id=ANY($1)")
            .bind(&expired)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE text_records SET content_expired_at=now() WHERE id=ANY($1)")
            .bind(&expired)
            .execute(&mut *tx)
            .await?;
    }
    // Active versions, immutable referenced chunks, cursors and lifetime account totals never reset.
    tx.commit().await?;
    Ok(())
}
