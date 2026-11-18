CREATE TABLE admin_audit_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_account_id bigint NOT NULL,
    target_account_id bigint NOT NULL,
    action text NOT NULL CHECK (
        action IN ('account_created', 'account_updated', 'account_deleted')
    ),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX admin_audit_log_created_idx ON admin_audit_log (created_at DESC, id DESC);

GRANT INSERT, UPDATE (role, enabled), DELETE ON accounts TO gb_app;
GRANT USAGE, SELECT ON SEQUENCE accounts_id_seq TO gb_app;
GRANT SELECT, INSERT ON admin_audit_log TO gb_app;
GRANT USAGE, SELECT ON SEQUENCE admin_audit_log_id_seq TO gb_app;
