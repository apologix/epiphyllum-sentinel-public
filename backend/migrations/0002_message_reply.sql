ALTER TABLE messages ADD COLUMN reply_to uuid REFERENCES messages;
CREATE UNIQUE INDEX one_response_per_turn ON messages(reply_to) WHERE role='assistant';
