ALTER TABLE auth_operator_bindings ADD COLUMN activation_started_at TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_operator_bindings ADD COLUMN activation_permissions TEXT NOT NULL DEFAULT '';
