CREATE INDEX phone_login_failures_stale_idx
    ON phone_login_failures(failed_at);
