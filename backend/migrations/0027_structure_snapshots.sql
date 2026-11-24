-- Mapa de estructura de solo metadatos (STR-01): snapshots versionados del
-- esqueleto (rutas, tipos, tamaños, fechas, permisos) de una raíz allowlisted
-- por servicio. Nunca se guarda contenido de archivos: no se abren.
CREATE TABLE structure_snapshots (
    id uuid PRIMARY KEY,
    service_id uuid NOT NULL REFERENCES services(id),
    root_alias text NOT NULL CHECK (root_alias IN ('demo-logs', 'external')),
    directory text NOT NULL DEFAULT '',
    node_count integer NOT NULL,
    truncated boolean NOT NULL DEFAULT false,
    nodes jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX structure_snapshots_service_idx
    ON structure_snapshots (service_id, root_alias, directory, created_at DESC);
