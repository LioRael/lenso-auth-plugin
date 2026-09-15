CREATE INDEX password_login_failures_stale_idx
    ON password_login_failures(failed_at);
