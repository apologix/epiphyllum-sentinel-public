-- Preserve every historical rule version; migrate only the active legacy name scopes.
CREATE TABLE unresolved_service_rules(
 original_version int NOT NULL REFERENCES business_rule_sets(version), ordinal bigint NOT NULL,
 rule jsonb NOT NULL, reason text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(original_version,ordinal)
);
CREATE TEMP TABLE current_service_rules ON COMMIT DROP AS
 SELECT version,definition FROM business_rule_sets ORDER BY version DESC LIMIT 1;
CREATE TEMP TABLE mapped_service_rules ON COMMIT DROP AS
 SELECT c.version,r.ordinal,r.rule,s.id AS service_id,
 jsonb_typeof(r.rule->'service')='string' AS has_legacy_scope
 FROM current_service_rules c CROSS JOIN LATERAL jsonb_array_elements(c.definition->'rules') WITH ORDINALITY r(rule,ordinal)
 LEFT JOIN services s ON lower(s.name)=lower(btrim(r.rule->>'service')) AND s.deleted_at IS NULL;
INSERT INTO unresolved_service_rules(original_version,ordinal,rule,reason)
 SELECT version,ordinal,rule,'service_not_found_or_ambiguous' FROM mapped_service_rules WHERE has_legacy_scope AND service_id IS NULL;
INSERT INTO business_rule_sets(version,definition)
 SELECT c.version+1,jsonb_set(c.definition,'{rules}',coalesce((
 SELECT jsonb_agg(CASE WHEN has_legacy_scope THEN (rule-'service')||jsonb_build_object('service_id',service_id) ELSE rule END ORDER BY ordinal)
 FROM mapped_service_rules WHERE NOT coalesce(has_legacy_scope,false) OR service_id IS NOT NULL
 ),'[]'::jsonb)) FROM current_service_rules c
 WHERE EXISTS(SELECT 1 FROM mapped_service_rules WHERE has_legacy_scope);
