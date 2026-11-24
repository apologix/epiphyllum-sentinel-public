-- Detención operativa de una revisión: los trabajos que todavía no se
-- enviaron pasan a 'stopped'. Los que ya están reservados o en vuelo no se
-- cancelan ni se reenvían; terminan y liquidan una sola vez.
ALTER TABLE analysis_jobs DROP CONSTRAINT job_state_valid;
ALTER TABLE analysis_jobs ADD CONSTRAINT job_state_valid CHECK(state IN('pending','preparing','eligible','reserved','in_flight','succeeded','failed','unknown','cached','skipped_budget','skipped_rate_limit','blocked_config','superseded','stopped'));

-- Evita que el encolado automático cree trabajos nuevos para un lote detenido.
-- Una nueva revisión manual borra la marca.
CREATE TABLE review_stops(run_id uuid PRIMARY KEY, stopped_at timestamptz NOT NULL DEFAULT now());

