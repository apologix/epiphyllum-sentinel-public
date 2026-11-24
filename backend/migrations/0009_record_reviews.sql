ALTER TABLE analysis_jobs ALTER COLUMN incident_id DROP NOT NULL;
ALTER TABLE analysis_jobs DROP CONSTRAINT analysis_jobs_kind_check;
ALTER TABLE analysis_jobs ADD CHECK(kind IN('analysis','chat','review'));
ALTER TABLE incidents DROP CONSTRAINT incidents_severity_check;
ALTER TABLE incidents ADD CHECK(severity IN('critical','high','medium','low','informational'));
ALTER TABLE incidents ADD COLUMN detection_origin text NOT NULL DEFAULT 'rule' CHECK(detection_origin IN('rule','ai','both'));
INSERT INTO rule_versions VALUES('AI',1,'{"kind":"validated_finding","version":1}','review-v1');
CREATE TABLE text_records(
 id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES demo_runs, event_id uuid REFERENCES events,
 record_seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE, content_hash text NOT NULL, original bytea,
 safe_text text, safe_hash text, byte_length bigint NOT NULL, parser text NOT NULL, diagnostic text,
 service text NOT NULL, source_id uuid NOT NULL REFERENCES sources, event_time timestamptz,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(), local_reason text,
 CHECK(original IS NULL OR octet_length(original)<=1048576));
CREATE TABLE record_locations(
 file_instance_id uuid NOT NULL REFERENCES file_instances, generation int NOT NULL, byte_start bigint NOT NULL,
 byte_end bigint NOT NULL, record_id uuid NOT NULL REFERENCES text_records, content_hash text NOT NULL,
 PRIMARY KEY(file_instance_id,generation,byte_start));
CREATE TABLE review_segments(
 id uuid PRIMARY KEY, record_id uuid NOT NULL REFERENCES text_records, revision int NOT NULL DEFAULT 1,
 ordinal int NOT NULL, byte_start int NOT NULL, byte_end int NOT NULL, content text NOT NULL, content_hash text NOT NULL,
 job_id uuid REFERENCES analysis_jobs, disposition text CHECK(disposition IN('clear','finding','inconclusive')),
 origin text CHECK(origin IN('mock','live')), UNIQUE(record_id,revision,ordinal), CHECK(byte_end>byte_start));
CREATE INDEX review_pending ON review_segments(record_id,ordinal) WHERE job_id IS NULL;
CREATE TABLE review_findings(
 id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES analysis_jobs, incident_id uuid NOT NULL REFERENCES incidents,
 category text NOT NULL, severity text NOT NULL, payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE finding_segments(finding_id uuid REFERENCES review_findings, segment_id uuid REFERENCES review_segments, PRIMARY KEY(finding_id,segment_id));
CREATE TABLE review_policy(version int PRIMARY KEY, definition jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
INSERT INTO review_policy VALUES(1,'{"effect":"allow","data_class":"synthetic","scope":"review"}');
CREATE TABLE business_rule_sets(version int PRIMARY KEY, definition jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
INSERT INTO business_rule_sets VALUES(1,'{"rules":[]}');
CREATE VIEW record_coverage AS
SELECT r.*,coalesce(s.total,0) AS segments,coalesce(s.completed,0) AS completed_segments,
 CASE WHEN r.local_reason='historical_original_not_recovered' THEN 'unavailable' WHEN r.local_reason IS NOT NULL THEN 'local'
 WHEN s.total>0 AND s.completed=s.total THEN
   CASE WHEN s.inconclusive THEN 'inconclusive' WHEN s.live THEN 'live' ELSE 'mock' END
 WHEN s.unknown THEN 'unknown' WHEN s.failed THEN 'failed' WHEN s.blocked THEN 'blocked'
 WHEN s.active THEN 'in_progress' ELSE 'pending' END AS coverage_state
FROM text_records r LEFT JOIN LATERAL(
 SELECT count(*) AS total,count(*) FILTER(WHERE disposition IS NOT NULL) AS completed,
 bool_or(disposition='inconclusive') AS inconclusive,bool_or(origin='live') AS live,
 bool_or(j.state='unknown') AS unknown,bool_or(j.state='failed') AS failed,
 bool_or(j.state IN('blocked_config','skipped_budget')) AS blocked,
 bool_or(j.state IN('preparing','reserved','in_flight')) AS active
 FROM review_segments s LEFT JOIN analysis_jobs j ON j.id=s.job_id WHERE s.record_id=r.id AND revision=1
)s ON true;

-- Existing summaries are never retroactively credited as primary coverage.
INSERT INTO text_records(id,run_id,event_id,content_hash,byte_length,parser,service,source_id,event_time,received_at,local_reason)
SELECT id,run_id,id,line_hash,byte_end-byte_start,parser,coalesce(service,'texto-sin-normalizar'),source_id,event_time,ingested_at,'historical_original_not_recovered' FROM events;
INSERT INTO record_locations(file_instance_id,generation,byte_start,byte_end,record_id,content_hash)
SELECT file_instance_id,generation,byte_start,byte_end,id,line_hash FROM events;
