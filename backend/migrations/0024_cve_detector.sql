ALTER TABLE services ADD COLUMN software_product text CHECK(software_product IS NULL OR octet_length(software_product) <= 120);
ALTER TABLE services ADD COLUMN software_version text CHECK(software_version IS NULL OR octet_length(software_version) <= 64);

CREATE TABLE cve_checks(
 id uuid PRIMARY KEY,
 service_id uuid NOT NULL REFERENCES services(id),
 product text NOT NULL,
 version text NOT NULL,
 state text NOT NULL CHECK(state IN ('completed','failed')),
 source text NOT NULL DEFAULT 'NVD',
 total_reported int NOT NULL DEFAULT 0,
 affecting_count int NOT NULL DEFAULT 0,
 error text,
 checked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cve_checks_service ON cve_checks(service_id, checked_at DESC);

CREATE TABLE cve_findings(
 id uuid PRIMARY KEY,
 check_id uuid NOT NULL REFERENCES cve_checks(id) ON DELETE CASCADE,
 service_id uuid NOT NULL REFERENCES services(id),
 cve_id text NOT NULL,
 severity text NOT NULL DEFAULT 'unknown',
 base_score numeric,
 summary text NOT NULL DEFAULT '',
 published timestamptz,
 affects boolean NOT NULL DEFAULT false,
 affected_range text,
 fixed_version text,
 refs jsonb NOT NULL DEFAULT '[]',
 UNIQUE(check_id, cve_id)
);
CREATE INDEX cve_findings_service ON cve_findings(service_id, affects DESC, published DESC);
