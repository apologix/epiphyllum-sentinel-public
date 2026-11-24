ALTER TABLE analysis_jobs ADD COLUMN route jsonb NOT NULL DEFAULT '{}';
ALTER TABLE analysis_attempts ADD COLUMN provider_metadata jsonb NOT NULL DEFAULT '{}';
ALTER TABLE analysis_attempts DROP CONSTRAINT attempt_amounts_valid;
ALTER TABLE analysis_attempts ADD CONSTRAINT attempt_amounts_valid CHECK(reserved_units>=0 AND accounted_units>=0 AND (input_tokens IS NULL OR input_tokens>=0) AND (output_tokens IS NULL OR output_tokens BETWEEN 0 AND 4096));
CREATE TABLE credential_versions(profile_id uuid NOT NULL, version int NOT NULL, ciphertext bytea NOT NULL, nonce bytea NOT NULL, PRIMARY KEY(profile_id,version));
INSERT INTO credential_versions SELECT p.id,p.version,c.ciphertext,c.nonce FROM provider_profiles p JOIN provider_credentials c ON c.profile_id=p.id WHERE p.version=(SELECT max(q.version) FROM provider_profiles q WHERE q.id=p.id);
INSERT INTO provider_profiles(id,version,profile) SELECT (value->>'id')::uuid,version,value FROM app_settings WHERE key='ai' ON CONFLICT DO NOTHING;
INSERT INTO credential_versions SELECT (s.value->>'id')::uuid,s.version,c.ciphertext,c.nonce FROM app_settings s JOIN provider_credentials c ON c.profile_id=(s.value->>'id')::uuid WHERE s.key='ai' ON CONFLICT DO NOTHING;

ALTER TABLE analyses DROP CONSTRAINT analyses_origin_check;
ALTER TABLE analyses ADD CONSTRAINT analyses_origin_check CHECK(origin IN('mock','live','cache','local'));
