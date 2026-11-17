CREATE TABLE accounts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email text NOT NULL UNIQUE CHECK (
        length(email) BETWEEN 3 AND 254 AND email = lower(btrim(email))
    ),
    password_hash text NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 500),
    role text NOT NULL CHECK (role IN ('admin', 'user')),
    enabled boolean NOT NULL DEFAULT true,
    totp_secret_ciphertext bytea,
    totp_nonce bytea CHECK (totp_nonce IS NULL OR octet_length(totp_nonce) = 12),
    totp_enrolled_at timestamptz,
    last_totp_step bigint NOT NULL DEFAULT -1,
    failure_window_started_at timestamptz,
    failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((totp_secret_ciphertext IS NULL) = (totp_nonce IS NULL))
);

CREATE INDEX accounts_admin_idx ON accounts (role) WHERE role = 'admin';

CREATE TABLE auth_sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    partial_expires_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (partial_expires_at IS NULL OR partial_expires_at > created_at)
);

CREATE INDEX auth_sessions_account_idx ON auth_sessions (account_id);

GRANT SELECT ON accounts TO gb_app;
GRANT UPDATE (
    totp_secret_ciphertext,
    totp_nonce,
    totp_enrolled_at,
    last_totp_step,
    failure_window_started_at,
    failed_login_count,
    locked_until
) ON accounts TO gb_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_sessions TO gb_app;
