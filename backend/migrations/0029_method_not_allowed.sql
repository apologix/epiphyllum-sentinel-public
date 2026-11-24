-- Corrección REVIEW-OBS-01 (P1 métodos): la clasificación cerrada gana el
-- valor method_not_allowed para cuando la ruta coincide con la superficie
-- declarada pero el método no está entre los permitidos de la entrada.
-- Conservadora: no reinterpreta clasificaciones históricas.
ALTER TABLE event_classifications DROP CONSTRAINT IF EXISTS event_classifications_classification_check;
ALTER TABLE event_classifications ADD CONSTRAINT event_classifications_classification_check
  CHECK(classification IN ('within_declared_boundary','outside_declared_boundary','method_not_allowed','encoded_traversal_attempt','ambiguous_normalization','unexpected_structure_change','sensitive_structure_change','authentication_anomaly','application_error_anomaly','boundary_unknown','insufficient_evidence'));
