-- Foreign-key checks during event retention/removal must not scan all evidence.
CREATE INDEX IF NOT EXISTS incident_events_event_id ON incident_events(event_id);
