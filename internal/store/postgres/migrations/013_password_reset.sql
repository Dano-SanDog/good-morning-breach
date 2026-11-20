CREATE TABLE password_reset_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX password_reset_tokens_account_idx ON password_reset_tokens (account_id, created_at);

GRANT SELECT, INSERT, DELETE ON password_reset_tokens TO gb_app;
GRANT UPDATE (password_hash) ON accounts TO gb_app;
