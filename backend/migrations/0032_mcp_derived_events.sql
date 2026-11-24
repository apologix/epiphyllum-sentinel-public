-- Contrato de eventos derivados MCP (planning/MCP-EVENT-CONTRACT.md §2.6):
-- hogar de los atributos cerrados del adaptador; incluye request_id para la
-- correlación Nginx -> Node sin reescribir históricos. Aditiva y anulable.
ALTER TABLE events ADD COLUMN attributes jsonb;
