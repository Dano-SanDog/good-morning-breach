DELETE FROM auth_sessions WHERE partial_expires_at IS NOT NULL;

ALTER TABLE auth_sessions
    DROP COLUMN partial_expires_at;

ALTER TABLE accounts
    DROP COLUMN totp_required,
    DROP COLUMN totp_secret_ciphertext,
    DROP COLUMN totp_nonce,
    DROP COLUMN totp_enrolled_at,
    DROP COLUMN last_totp_step;

GRANT UPDATE (failure_window_started_at, failed_login_count, locked_until) ON accounts TO gb_app
