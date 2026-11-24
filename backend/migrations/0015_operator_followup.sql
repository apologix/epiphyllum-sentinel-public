ALTER TABLE incidents ADD COLUMN followup_state text NOT NULL DEFAULT 'open' CHECK (followup_state IN ('open','acknowledged','closed'));
CREATE TABLE incident_actions (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 incident_id uuid NOT NULL REFERENCES incidents(id),
 action text NOT NULL CHECK(action IN ('acknowledged','closed','reopened','observation')),
 observation text NOT NULL DEFAULT '' CHECK(char_length(observation)<=2000),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE notifications (
 incident_id uuid PRIMARY KEY REFERENCES incidents(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 read_at timestamptz
);
CREATE FUNCTION notify_new_incident() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO notifications(incident_id) VALUES(NEW.id) ON CONFLICT DO NOTHING;
 RETURN NEW;
END $$;
CREATE TRIGGER incident_notification AFTER INSERT ON incidents FOR EACH ROW EXECUTE FUNCTION notify_new_incident();
