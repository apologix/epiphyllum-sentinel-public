-- Preserve the original finding and its incident; expose each cited record separately.
CREATE TABLE record_incidents (
 record_id uuid PRIMARY KEY REFERENCES text_records,
 incident_id uuid NOT NULL UNIQUE REFERENCES incidents
);
CREATE TABLE incident_finding_records (
 finding_id uuid NOT NULL REFERENCES review_findings,
 record_id uuid NOT NULL REFERENCES record_incidents(record_id),
 PRIMARY KEY(finding_id,record_id)
);
ALTER TABLE incidents ADD COLUMN historical_group boolean NOT NULL DEFAULT false;
CREATE TEMP TABLE split_records ON COMMIT DROP AS
 SELECT DISTINCT ON (r.id) r.id AS record_id, gen_random_uuid() AS incident_id,
 r.run_id,r.service,r.received_at,f.id AS finding_id,f.severity,f.payload,f.category
 FROM review_findings f JOIN finding_segments fs ON fs.finding_id=f.id
 JOIN review_segments s ON s.id=fs.segment_id JOIN text_records r ON r.id=s.record_id
 ORDER BY r.id, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC;
INSERT INTO incidents(id,incident_key,run_id,rule_id,rule_version,group_key,severity,title,opened_at,last_match_at,deterministic_reason,detection_origin,analyzed_version)
 SELECT incident_id,md5('record:'||record_id::text),run_id,'AI',1,jsonb_build_object('service',service,'record_id',record_id),severity,payload->>'title',received_at,received_at,jsonb_build_object('source','historical_review','reason',payload->>'reason'), 'ai',1 FROM split_records;
INSERT INTO record_incidents SELECT record_id,incident_id FROM split_records;
INSERT INTO incident_finding_records SELECT DISTINCT f.id,s.record_id FROM review_findings f JOIN finding_segments fs ON fs.finding_id=f.id JOIN review_segments s ON s.id=fs.segment_id;
INSERT INTO incident_relations(from_id,to_id,relation)
 SELECT DISTINCT ri.incident_id,f.incident_id,'historical_source' FROM incident_finding_records l JOIN record_incidents ri ON ri.record_id=l.record_id JOIN review_findings f ON f.id=l.finding_id WHERE ri.incident_id<>f.incident_id ON CONFLICT DO NOTHING;
UPDATE incidents i SET historical_group=true WHERE i.detection_origin='ai' AND EXISTS(SELECT 1 FROM review_findings f WHERE f.incident_id=i.id);
