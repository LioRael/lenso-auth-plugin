ALTER TABLE identity_subjects ADD COLUMN disabled_reason text;
ALTER TABLE identity_subjects ADD COLUMN disabled_until timestamptz;

CREATE INDEX identity_subjects_created_idx ON identity_subjects(created_at, subject_id);
CREATE INDEX auth_sessions_created_idx ON auth_sessions(created_at, session_id);
