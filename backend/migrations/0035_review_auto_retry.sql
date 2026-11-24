-- Contador de reintentos automáticos por registro de revisión. No cuenta los
-- reintentos manuales históricos: cada registro recibe hasta tres intentos
-- automáticos desde que se activa esta política.
ALTER TABLE text_records ADD COLUMN auto_retry_count int NOT NULL DEFAULT 0 CHECK (auto_retry_count BETWEEN 0 AND 3);
