use crate::App;
use serde_json::Value;

pub async fn summary(app: &App) -> Result<Value, sqlx::Error> {
    sqlx::query_scalar(r#"
WITH hours AS (
    SELECT generate_series(date_trunc('hour',now())-interval '23 hours',date_trunc('hour',now()),interval '1 hour') AS hour
), activity AS (
    SELECT date_trunc('hour',ingested_at) AS hour,count(*) AS events
    FROM events WHERE ingested_at>=date_trunc('hour',now())-interval '23 hours' GROUP BY 1
), event_counts AS (
    SELECT event_type,count(*) AS events FROM events GROUP BY event_type
), triggers AS (
    SELECT i.id,e.event_type FROM incidents i
    JOIN events e ON e.id=(i.deterministic_reason->>'trigger_event_id')::uuid
), incident_counts AS (
    SELECT event_type,count(*) AS incidents FROM triggers GROUP BY event_type
), session_attempts AS (
    SELECT a.*,t.event_type FROM analysis_attempts a
    JOIN budget_reservations r ON r.attempt_id=a.id AND r.account_scope='session' AND r.account_key=$1
    JOIN analysis_jobs j ON j.id=a.job_id JOIN triggers t ON t.id=j.incident_id
), costs AS (
    SELECT event_type,coalesce(sum(accounted_units),0)::bigint AS spent_units,
           coalesce(sum(CASE WHEN state IN('reserved','in_flight') THEN reserved_units ELSE 0 END),0)::bigint AS reserved_units,
           count(*) FILTER(WHERE sent_at IS NOT NULL) AS calls,
           bool_or(usage_estimated AND accounted_units>0) AS estimated
    FROM session_attempts GROUP BY event_type
)
SELECT jsonb_build_object(
    'updated_at',now(),
    'totals',jsonb_build_object('events',(SELECT count(*) FROM events),
        'incidents',(SELECT count(*) FROM incidents WHERE NOT historical_group),
        'priority_incidents',(SELECT count(*) FROM incidents WHERE NOT historical_group AND severity IN('critical','high')),
        'runs',(SELECT count(*) FROM demo_runs),
        'last_ingested_at',(SELECT max(ingested_at) FROM events)),
    'active_cost',(SELECT jsonb_build_object('spent_units',coalesce(sum(a.accounted_units),0)::bigint,
        'reserved_units',coalesce(sum(CASE WHEN a.state IN('reserved','in_flight') THEN a.reserved_units ELSE 0 END),0)::bigint)
        FROM analysis_attempts a JOIN analysis_jobs j ON j.id=a.job_id JOIN budget_reservations r ON r.attempt_id=a.id
        WHERE r.account_scope='session' AND r.account_key=$1 AND
        (EXISTS(SELECT 1 FROM incidents i WHERE i.id=j.incident_id) OR EXISTS(SELECT 1 FROM review_segments s WHERE s.job_id=j.id))),
    'budget',coalesce((SELECT to_jsonb(a)||jsonb_build_object('limit_units',NULL,'remaining_units',NULL,'cap_enabled',false)
        FROM budget_accounts a WHERE scope='session' AND scope_key=$1),
        jsonb_build_object('limit_units',0,'spent_units',0,'reserved_units',0,'remaining_units',0)),
    'timeline',(SELECT jsonb_agg(jsonb_build_object('hour',h.hour,'events',coalesce(a.events,0)) ORDER BY h.hour)
        FROM hours h LEFT JOIN activity a USING(hour)),
    'severity',(SELECT jsonb_agg(jsonb_build_object('severity',s.severity,'count',(SELECT count(*) FROM incidents i WHERE NOT i.historical_group AND i.severity=s.severity)) ORDER BY s.ordinal)
        FROM (VALUES('critical',1),('high',2),('medium',3),('low',4),('informational',5))s(severity,ordinal)),
    'by_event_type',(SELECT jsonb_agg(jsonb_build_object('event_type',t.event_type,
        'events',coalesce(e.events,0),'incidents',coalesce(i.incidents,0),
        'spent_units',coalesce(c.spent_units,0),'reserved_units',coalesce(c.reserved_units,0),
        'calls',coalesce(c.calls,0),'estimated',coalesce(c.estimated,false)) ORDER BY t.ordinal)
        FROM (VALUES('auth.failed',1),('auth.success',2),('app.error',3),('system.notice',4))t(event_type,ordinal)
        LEFT JOIN event_counts e USING(event_type) LEFT JOIN incident_counts i USING(event_type) LEFT JOIN costs c USING(event_type)),
    'notes',coalesce((SELECT jsonb_build_object('text',value->>'text','version',version,'updated_at',updated_at)
        FROM app_settings WHERE key='dashboard_notes'),jsonb_build_object('text','','version',0,'updated_at',NULL))
)
"#).bind(&app.config.session_id).fetch_one(&app.pool).await
}
