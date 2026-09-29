ALTER TABLE identity_subjects ADD COLUMN display_name TEXT;
ALTER TABLE identity_subjects ADD COLUMN avatar_url TEXT;
ALTER TABLE identity_subjects ADD COLUMN profile_revision BIGINT NOT NULL DEFAULT 0 CHECK (profile_revision >= 0);
