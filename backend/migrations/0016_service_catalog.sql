CREATE TABLE services(
 id uuid PRIMARY KEY, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 description text NOT NULL DEFAULT '' CHECK(octet_length(description)<=4096),
 enabled boolean NOT NULL DEFAULT true, version int NOT NULL DEFAULT 1 CHECK(version>0),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz
);
CREATE UNIQUE INDEX services_live_name ON services(lower(btrim(name))) WHERE deleted_at IS NULL;
CREATE INDEX services_name_page ON services(lower(name),id);
CREATE TABLE service_revisions(
 service_id uuid NOT NULL REFERENCES services, version int NOT NULL, name text NOT NULL,
 description text NOT NULL, context text NOT NULL CHECK(length(context)<=4000 AND octet_length(context)<=8192),
 context_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(service_id,version)
);
ALTER TABLE sources ADD COLUMN service_id uuid REFERENCES services;
ALTER TABLE sources ADD COLUMN kind text NOT NULL DEFAULT 'folder' CHECK(kind IN('folder','mcp'));
ALTER TABLE sources ADD COLUMN enabled boolean NOT NULL DEFAULT false;
ALTER TABLE sources ADD COLUMN config jsonb NOT NULL DEFAULT '{}';
ALTER TABLE sources ADD COLUMN version int NOT NULL DEFAULT 1;
ALTER TABLE sources ADD COLUMN capture_version int NOT NULL DEFAULT 1;
ALTER TABLE sources ADD COLUMN deleted_at timestamptz;
CREATE INDEX sources_service ON sources(service_id) WHERE deleted_at IS NULL;
CREATE TABLE source_credentials(source_id uuid PRIMARY KEY REFERENCES sources,ciphertext bytea NOT NULL,nonce bytea NOT NULL);
CREATE TABLE source_revisions(source_id uuid REFERENCES sources,version int NOT NULL,config jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(source_id,version));
ALTER TABLE events ADD COLUMN service_id uuid REFERENCES services;
ALTER TABLE text_records ADD COLUMN service_id uuid REFERENCES services;
CREATE INDEX events_service_id_seq ON events(service_id,ingest_seq);
CREATE INDEX records_service_id_seq ON text_records(service_id,record_seq);
CREATE TABLE incident_services(incident_id uuid REFERENCES incidents,service_id uuid REFERENCES services,PRIMARY KEY(incident_id,service_id));
CREATE INDEX incident_services_service ON incident_services(service_id,incident_id);
CREATE TABLE service_requests(kind text NOT NULL,key uuid NOT NULL,payload_hash text NOT NULL,resource_id uuid NOT NULL,PRIMARY KEY(kind,key));
CREATE TABLE mcp_captures(source_id uuid REFERENCES sources,source_version int NOT NULL,resource_uri text NOT NULL,content_hash text NOT NULL,captured_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(source_id,source_version,resource_uri));
CREATE TABLE mcp_record_locations(source_id uuid REFERENCES sources,source_version int NOT NULL,external_id text NOT NULL,record_id uuid REFERENCES text_records,content_hash text NOT NULL,PRIMARY KEY(source_id,source_version,external_id));
-- One legacy source contains multiple services. Preserve physical cursors and associate each record separately.
INSERT INTO services(id,name)
 SELECT gen_random_uuid(),min(name) FROM (
 SELECT DISTINCT btrim(service) AS name FROM events WHERE service IS NOT NULL AND length(btrim(service)) BETWEEN 1 AND 128
 UNION SELECT DISTINCT btrim(service) FROM text_records WHERE length(btrim(service)) BETWEEN 1 AND 128
 UNION SELECT DISTINCT btrim(group_key->>'service') FROM incidents WHERE length(btrim(group_key->>'service')) BETWEEN 1 AND 128
 ) names WHERE name<>'texto-sin-normalizar' GROUP BY lower(name) HAVING count(DISTINCT name)=1;
INSERT INTO service_revisions(service_id,version,name,description,context,context_hash)
 SELECT id,1,name,'','','e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' FROM services;
UPDATE events e SET service_id=s.id FROM services s WHERE lower(btrim(e.service))=lower(s.name);
UPDATE text_records r SET service_id=s.id FROM services s WHERE lower(btrim(r.service))=lower(s.name);
INSERT INTO incident_services SELECT DISTINCT ie.incident_id,e.service_id FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE e.service_id IS NOT NULL ON CONFLICT DO NOTHING;
INSERT INTO incident_services SELECT DISTINCT ri.incident_id,r.service_id FROM record_incidents ri JOIN text_records r ON r.id=ri.record_id WHERE r.service_id IS NOT NULL ON CONFLICT DO NOTHING;
INSERT INTO incident_services SELECT DISTINCT i.id,s.id FROM incidents i JOIN services s ON lower(s.name)=lower(btrim(i.group_key->>'service')) ON CONFLICT DO NOTHING;

CREATE OR REPLACE VIEW record_coverage AS
SELECT r.id,r.run_id,r.event_id,r.record_seq,r.content_hash,r.original,r.safe_text,r.safe_hash,r.byte_length,r.parser,r.diagnostic,r.service,r.source_id,r.event_time,r.received_at,r.local_reason,coalesce(s.total,0) AS segments,coalesce(s.completed,0) AS completed_segments,
 CASE WHEN r.local_reason='historical_original_not_recovered' THEN 'unavailable' WHEN r.local_reason IS NOT NULL THEN 'local'
 WHEN s.total>0 AND s.completed=s.total THEN
   CASE WHEN s.inconclusive THEN 'inconclusive' WHEN s.live AND s.mock THEN 'mixed' WHEN s.live THEN 'live' ELSE 'mock' END
 WHEN s.unknown THEN 'unknown' WHEN s.failed THEN 'failed' WHEN s.blocked THEN 'blocked'
 WHEN s.active THEN 'in_progress' ELSE 'pending' END AS coverage_state,r.service_id
FROM text_records r LEFT JOIN LATERAL(
 SELECT count(*) AS total,count(*) FILTER(WHERE disposition IS NOT NULL) AS completed,
 bool_or(disposition='inconclusive') AS inconclusive,bool_or(origin='live') AS live,bool_or(origin='mock') AS mock,
 bool_or(j.state='unknown') AS unknown,bool_or(j.state='failed') AS failed,
 bool_or(j.state IN('blocked_config','skipped_budget')) AS blocked,
 bool_or(j.state IN('preparing','reserved','in_flight')) AS active
 FROM review_segments s LEFT JOIN analysis_jobs j ON j.id=s.job_id WHERE s.record_id=r.id AND s.revision=(SELECT max(s2.revision) FROM review_segments s2 WHERE s2.record_id=r.id)
)s ON true;


ALTER TABLE file_instances ADD COLUMN capture_version int NOT NULL DEFAULT 1;
ALTER TABLE file_instances DROP CONSTRAINT file_instances_source_id_device_inode_generation_key;
ALTER TABLE file_instances ADD UNIQUE(source_id,capture_version,device,inode,generation);
CREATE TABLE job_services(job_id uuid REFERENCES analysis_jobs,service_id uuid NOT NULL,service_version int NOT NULL,PRIMARY KEY(job_id,service_id),FOREIGN KEY(service_id,service_version) REFERENCES service_revisions(service_id,version));

-- Record context ownership for pre-catalogue jobs; snapshots remain immutable.
INSERT INTO job_services(job_id,service_id,service_version)
SELECT DISTINCT j.id,s.id,s.version FROM analysis_jobs j JOIN incident_services z ON z.incident_id=j.incident_id JOIN services s ON s.id=z.service_id ON CONFLICT DO NOTHING;
INSERT INTO job_services(job_id,service_id,service_version)
SELECT DISTINCT j.id,s.id,s.version FROM analysis_jobs j JOIN review_segments seg ON seg.job_id=j.id JOIN text_records r ON r.id=seg.record_id JOIN services s ON s.id=r.service_id ON CONFLICT DO NOTHING;
