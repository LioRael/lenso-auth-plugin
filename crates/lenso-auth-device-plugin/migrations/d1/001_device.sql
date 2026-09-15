CREATE TABLE auth_device_schema(version INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE auth_devices (
 device_id TEXT NOT NULL,
 subject_id TEXT NOT NULL,
 trusted_at TEXT,
 primary_at TEXT,
 last_seen_ip TEXT,
 last_seen_user_agent TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(subject_id, device_id)
);
CREATE INDEX auth_devices_subject_updated_idx ON auth_devices(subject_id, updated_at DESC);
CREATE UNIQUE INDEX auth_devices_one_primary_per_subject_idx ON auth_devices(subject_id) WHERE primary_at IS NOT NULL;
INSERT INTO auth_device_schema VALUES(1,'a406b7c5c8b3d1f656723dda5a41a912d4f434031fa9dfcf6e6372c0dc128994');
