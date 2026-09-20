ALTER TABLE oauth_flows
    ADD COLUMN revoked_at timestamptz;
