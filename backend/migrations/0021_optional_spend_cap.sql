ALTER TABLE budget_accounts
  ADD COLUMN cap_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN cap_baseline_spent_units bigint NOT NULL DEFAULT 0 CHECK (cap_baseline_spent_units >= 0),
  ADD COLUMN cap_version integer NOT NULL DEFAULT 1 CHECK (cap_version > 0);
