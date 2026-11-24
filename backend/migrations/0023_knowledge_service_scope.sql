ALTER TABLE knowledge_documents ADD COLUMN service_id uuid REFERENCES services(id);
CREATE INDEX knowledge_documents_service ON knowledge_documents(service_id);
