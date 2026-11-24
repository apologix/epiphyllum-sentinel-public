-- Real sources are explicit and immutable at the API boundary; existing rows remain synthetic.
ALTER TABLE sources ADD COLUMN data_class text NOT NULL DEFAULT 'synthetic' CHECK(data_class IN ('synthetic','real'));
ALTER TABLE events ADD COLUMN data_class text NOT NULL DEFAULT 'synthetic' CHECK(data_class IN ('synthetic','real'));
ALTER TABLE text_records ADD COLUMN data_class text NOT NULL DEFAULT 'synthetic' CHECK(data_class IN ('synthetic','real'));
ALTER TABLE text_records ADD COLUMN content_expired_at timestamptz;
ALTER TABLE analysis_jobs ADD COLUMN snapshot_expired_at timestamptz;
CREATE INDEX real_pending_records ON text_records(received_at) WHERE data_class='real' AND content_expired_at IS NULL;
CREATE FUNCTION real_queue_bytes() RETURNS bigint LANGUAGE sql STABLE AS $$
 SELECT coalesce(sum(octet_length(s.content)),0)::bigint FROM review_segments s JOIN text_records r ON r.id=s.record_id WHERE r.data_class='real' AND r.content_expired_at IS NULL
$$;
CREATE OR REPLACE VIEW record_coverage AS
SELECT r.id,r.run_id,r.event_id,r.record_seq,r.content_hash,r.original,r.safe_text,r.safe_hash,r.byte_length,r.parser,r.diagnostic,r.service,r.source_id,r.event_time,r.received_at,r.local_reason,coalesce(s.total,0) AS segments,coalesce(s.completed,0) AS completed_segments,
 CASE WHEN r.local_reason='historical_original_not_recovered' THEN 'unavailable' WHEN r.local_reason IS NOT NULL THEN 'local'
 WHEN s.total>0 AND s.completed=s.total THEN
   CASE WHEN s.inconclusive THEN 'inconclusive' WHEN s.live AND s.mock THEN 'mixed' WHEN s.live THEN 'live' ELSE 'mock' END
 WHEN s.unknown THEN 'unknown' WHEN s.failed THEN 'failed' WHEN s.blocked THEN 'blocked'
 WHEN s.active THEN 'in_progress' ELSE 'pending' END AS coverage_state,r.service_id,r.data_class,r.content_expired_at
FROM text_records r LEFT JOIN LATERAL(
 SELECT count(*) AS total,count(*) FILTER(WHERE disposition IS NOT NULL) AS completed,
 bool_or(disposition='inconclusive') AS inconclusive,bool_or(origin='live') AS live,bool_or(origin='mock') AS mock,
 bool_or(j.state='unknown') AS unknown,bool_or(j.state='failed') AS failed,
 bool_or(j.state IN('blocked_config','skipped_budget')) AS blocked,
 bool_or(j.state IN('preparing','reserved','in_flight')) AS active
 FROM review_segments s LEFT JOIN analysis_jobs j ON j.id=s.job_id WHERE s.record_id=r.id AND s.revision=(SELECT max(s2.revision) FROM review_segments s2 WHERE s2.record_id=r.id)
)s ON true;
