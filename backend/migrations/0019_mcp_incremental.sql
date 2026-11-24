-- MCP events have durable remote locations instead of a local file descriptor.
ALTER TABLE events ALTER COLUMN file_instance_id DROP NOT NULL;
ALTER TABLE mcp_record_locations ADD COLUMN remote_file_id text;
ALTER TABLE mcp_record_locations ADD COLUMN byte_start bigint;
ALTER TABLE mcp_record_locations ADD COLUMN byte_end bigint;
CREATE TABLE mcp_incremental_cursors (
 source_id uuid NOT NULL REFERENCES sources,
 capture_version int NOT NULL,
 cursor text,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(source_id,capture_version)
);
