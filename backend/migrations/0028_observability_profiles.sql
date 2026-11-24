-- Límites observables por servicio (OBS-01): perfil versionado de entradas
-- tipadas (http/filesystem/authentication/application/source), evidencia HTTP
-- estructurada en eventos y clasificación determinista persistida.
-- Conservadora: los servicios existentes empiezan sin entradas («sin límites
-- declarados»); ningún análisis histórico se reinterpreta.

ALTER TABLE events ADD COLUMN IF NOT EXISTS http jsonb;

CREATE TABLE IF NOT EXISTS service_profile_entries(
  entry_id uuid NOT NULL,
  revision int NOT NULL CHECK(revision>=1),
  service_id uuid NOT NULL REFERENCES services(id),
  scope text NOT NULL CHECK(scope IN ('http','filesystem','authentication','application','source')),
  entry_kind text NOT NULL CHECK(entry_kind IN ('route','zone','note')),
  config jsonb NOT NULL,
  description text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','retired')),
  created_by text NOT NULL DEFAULT 'operator',
  config_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(entry_id,revision)
);
CREATE INDEX IF NOT EXISTS profile_entries_service ON service_profile_entries(service_id,scope,entry_id,revision DESC);

CREATE TABLE IF NOT EXISTS event_classifications(
  event_id uuid PRIMARY KEY REFERENCES events(id),
  service_id uuid,
  classification text NOT NULL CHECK(classification IN ('within_declared_boundary','outside_declared_boundary','encoded_traversal_attempt','ambiguous_normalization','unexpected_structure_change','sensitive_structure_change','authentication_anomaly','application_error_anomaly','boundary_unknown','insufficient_evidence')),
  profile_fingerprint text NOT NULL DEFAULT '',
  matched_entry_id uuid,
  matched_revision int,
  reason jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS event_classifications_service ON event_classifications(service_id,classification,created_at DESC);
