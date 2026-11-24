-- Mixed mock/live segments never count as complete external coverage.
CREATE OR REPLACE VIEW record_coverage AS
SELECT r.*,coalesce(s.total,0) AS segments,coalesce(s.completed,0) AS completed_segments,
 CASE WHEN r.local_reason='historical_original_not_recovered' THEN 'unavailable' WHEN r.local_reason IS NOT NULL THEN 'local'
 WHEN s.total>0 AND s.completed=s.total THEN
   CASE WHEN s.inconclusive THEN 'inconclusive' WHEN s.live AND s.mock THEN 'mixed' WHEN s.live THEN 'live' ELSE 'mock' END
 WHEN s.unknown THEN 'unknown' WHEN s.failed THEN 'failed' WHEN s.blocked THEN 'blocked'
 WHEN s.active THEN 'in_progress' ELSE 'pending' END AS coverage_state
FROM text_records r LEFT JOIN LATERAL(
 SELECT count(*) AS total,count(*) FILTER(WHERE disposition IS NOT NULL) AS completed,
 bool_or(disposition='inconclusive') AS inconclusive,bool_or(origin='live') AS live,bool_or(origin='mock') AS mock,
 bool_or(j.state='unknown') AS unknown,bool_or(j.state='failed') AS failed,
 bool_or(j.state IN('blocked_config','skipped_budget')) AS blocked,
 bool_or(j.state IN('preparing','reserved','in_flight')) AS active
 FROM review_segments s LEFT JOIN analysis_jobs j ON j.id=s.job_id WHERE s.record_id=r.id AND revision=1
)s ON true;

-- Stable keyset pagination for cited segments, including many from one record.
ALTER TABLE review_segments ADD COLUMN segment_seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE;
