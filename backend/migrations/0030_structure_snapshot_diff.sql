-- Seguimiento REVIEW-OBS-01: la semántica de ventana de las plantillas de
-- estructura necesita contar rutas nuevas de capturas recientes del mismo
-- grupo, así que el diff clasificado de cada captura queda persistido.
-- Conservadora: las capturas históricas quedan con diff vacío y aportan 0
-- a la acumulación (sus diffs no se reinterpretan).
ALTER TABLE structure_snapshots ADD COLUMN IF NOT EXISTS diff jsonb NOT NULL DEFAULT '{}'::jsonb;
