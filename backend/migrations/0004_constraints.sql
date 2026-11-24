ALTER TABLE analysis_jobs ADD CONSTRAINT job_state_valid CHECK(state IN('pending','preparing','eligible','reserved','in_flight','succeeded','failed','unknown','cached','skipped_budget','skipped_rate_limit','blocked_config','superseded'));
ALTER TABLE analysis_attempts ADD CONSTRAINT attempt_state_valid CHECK(state IN('reserved','in_flight','succeeded','failed','unknown'));
ALTER TABLE analysis_attempts ADD CONSTRAINT attempt_amounts_valid CHECK(reserved_units>=0 AND accounted_units>=0 AND (input_tokens IS NULL OR input_tokens>=0) AND (output_tokens IS NULL OR output_tokens BETWEEN 0 AND 800));
ALTER TABLE budget_reservations ADD CONSTRAINT reservation_valid CHECK(amount_units>=0 AND state IN('reserved','settled'));
ALTER TABLE detection_work ADD CONSTRAINT work_state_valid CHECK(state IN('pending','processing','done','failed'));
ALTER TABLE incidents ADD CONSTRAINT incident_versions_valid CHECK(evidence_version>=1 AND report_version>=1 AND rule_version>=1);
ALTER TABLE knowledge_revisions ADD CONSTRAINT revision_valid CHECK(revision>=1);
ALTER TABLE provider_profiles ADD CONSTRAINT profile_version_valid CHECK(version>=1);
