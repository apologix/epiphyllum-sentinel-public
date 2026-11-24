ALTER TABLE sources ADD COLUMN analysis jsonb NOT NULL DEFAULT '{"system":"Sin especificar","protocol":"Sin especificar","adapter":"auto","context":"","rules":[]}';
ALTER TABLE source_revisions ADD COLUMN analysis jsonb NOT NULL DEFAULT '{"system":"Sin especificar","protocol":"Sin especificar","adapter":"auto","context":"","rules":[]}';
ALTER TABLE events ADD COLUMN source_version int;
ALTER TABLE text_records ADD COLUMN source_version int;
CREATE FUNCTION stamp_source_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 SELECT version INTO NEW.source_version FROM sources WHERE id=NEW.source_id;
 RETURN NEW;
END $$;
CREATE TRIGGER events_source_version BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION stamp_source_version();
CREATE TRIGGER records_source_version BEFORE INSERT ON text_records FOR EACH ROW EXECUTE FUNCTION stamp_source_version();
CREATE TABLE source_checks(
 source_id uuid PRIMARY KEY REFERENCES sources(id),
 source_version int NOT NULL,
 checked_at timestamptz NOT NULL DEFAULT now(),
 result jsonb NOT NULL
);
