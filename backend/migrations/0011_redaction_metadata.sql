-- Password/secret assignments are now redacted in addition to the historical patterns.
ALTER TABLE text_records ADD COLUMN redaction_version int NOT NULL DEFAULT 2;
ALTER TABLE analysis_jobs ALTER COLUMN redaction_version SET DEFAULT 2;
