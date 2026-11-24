ALTER TABLE services DROP CONSTRAINT IF EXISTS services_software_origin_check;
ALTER TABLE services ADD CONSTRAINT services_software_origin_check CHECK (software_origin IN ('operator', 'banner', 'mcp'));
