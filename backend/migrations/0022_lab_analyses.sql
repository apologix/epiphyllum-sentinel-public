CREATE TABLE lab_analyses(
 id uuid PRIMARY KEY,
 service_id uuid NOT NULL REFERENCES services(id),
 profile text NOT NULL CHECK(profile IN ('event_correlation','exposure_inventory','config_audit','known_vulns')),
 profile_version int NOT NULL DEFAULT 1 CHECK(profile_version>0),
 objective text NOT NULL DEFAULT '' CHECK(octet_length(objective)<=2000),
 scope jsonb NOT NULL,
 state text NOT NULL CHECK(state IN ('running','completed','blocked','failed')),
 summary text,
 limitations jsonb NOT NULL DEFAULT '[]',
 findings jsonb NOT NULL DEFAULT '[]',
 stats jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz
);
CREATE INDEX lab_analyses_created ON lab_analyses(created_at DESC,id DESC);
CREATE INDEX lab_analyses_service ON lab_analyses(service_id,created_at DESC);
