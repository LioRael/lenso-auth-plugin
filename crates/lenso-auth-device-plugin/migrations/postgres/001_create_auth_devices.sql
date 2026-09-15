CREATE TABLE auth_devices (
    device_id text NOT NULL,
    subject_id text NOT NULL,
    trusted_at timestamptz,
    primary_at timestamptz,
    last_seen_ip text,
    last_seen_user_agent text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (subject_id, device_id)
);

CREATE INDEX auth_devices_subject_updated_idx
    ON auth_devices(subject_id, updated_at DESC);
