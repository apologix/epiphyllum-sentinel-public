-- A browser tab owns its presence; abandoned tabs expire without canceling a sent request.
CREATE TABLE chat_worker_presence (
 incident_id uuid NOT NULL REFERENCES incidents,
 visitor_id uuid NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY (incident_id,visitor_id)
);
CREATE INDEX chat_worker_presence_expiry ON chat_worker_presence(expires_at);
