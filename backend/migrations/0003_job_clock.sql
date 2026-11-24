ALTER TABLE analysis_jobs ALTER COLUMN created_at SET DEFAULT clock_timestamp();
CREATE INDEX attempts_sent_at ON analysis_attempts(sent_at DESC) WHERE sent_at IS NOT NULL;
CREATE INDEX detection_pending_seq ON detection_work(ingest_seq) WHERE state='pending';
