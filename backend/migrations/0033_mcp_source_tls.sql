-- Preservar la CA efectiva en las fuentes MCP existentes antes de retirar el
-- registro global de app_settings. Las fuentes que no tengan CA propia siguen
-- usando MCP_LAB_CA_FILE o la CA empaquetada (lab/lab-ca.pem).
DO $$
DECLARE
    v_ca text;
BEGIN
    SELECT NULLIF(btrim(value->>'ca_pem'), '') INTO v_ca
    FROM app_settings
    WHERE key = 'lab';

    IF v_ca IS NOT NULL THEN
        UPDATE sources
        SET config = jsonb_set(config, '{ca_pem}', to_jsonb(v_ca), true)
        WHERE kind = 'mcp'
          AND config->>'mode' = 'incremental_lab'
          AND NOT (config ? 'ca_pem');

        UPDATE source_revisions sr
        SET config = jsonb_set(sr.config, '{ca_pem}', to_jsonb(v_ca), true)
        FROM sources s
        WHERE sr.source_id = s.id
          AND s.kind = 'mcp'
          AND sr.config->>'mode' = 'incremental_lab'
          AND NOT (sr.config ? 'ca_pem');
    END IF;

    DELETE FROM app_settings WHERE key = 'lab';
END $$;
