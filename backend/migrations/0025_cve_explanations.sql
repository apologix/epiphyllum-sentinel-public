CREATE TABLE cve_explanations(
 id uuid PRIMARY KEY,
 finding_id uuid NOT NULL REFERENCES cve_findings(id),
 service_id uuid NOT NULL REFERENCES services(id),
 question text NOT NULL CHECK(octet_length(question) BETWEEN 1 AND 1000),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','generating','ready','blocked','failed')),
 answer text,
 human_checks jsonb NOT NULL DEFAULT '[]',
 origin text,
 model text,
 reason text,
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz
);
CREATE INDEX cve_explanations_pending ON cve_explanations(created_at) WHERE state = 'pending';
CREATE INDEX cve_explanations_finding ON cve_explanations(finding_id, created_at DESC);
