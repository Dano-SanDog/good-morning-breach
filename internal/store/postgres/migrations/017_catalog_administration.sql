ALTER TABLE admin_audit_log
    ALTER COLUMN target_account_id DROP NOT NULL;

ALTER TABLE admin_audit_log
    ADD COLUMN target_kind text NOT NULL DEFAULT 'account'
        CHECK (target_kind IN ('account', 'category', 'source')),
    ADD COLUMN target_id text;

ALTER TABLE admin_audit_log
    ADD CONSTRAINT admin_audit_log_target_check
    CHECK (target_kind <> 'account' OR target_account_id IS NOT NULL);

ALTER TABLE admin_audit_log
    DROP CONSTRAINT admin_audit_log_action_check;

ALTER TABLE admin_audit_log
    ADD CONSTRAINT admin_audit_log_action_check CHECK (action IN (
        'account_created', 'account_updated', 'account_deleted',
        'category_created', 'category_updated', 'category_deleted',
        'source_created', 'source_updated', 'source_deleted'
    ));

CREATE UNIQUE INDEX categories_lower_name_idx ON categories (lower(name));

GRANT INSERT, DELETE, UPDATE (name, enabled, updated_at) ON categories TO gb_app;

GRANT INSERT, DELETE, UPDATE (
    name, address, license_name, license_url, permitted_use, attribution,
    content_policy, poll_interval_seconds, enabled, format,
    require_complete_title, updated_at
) ON data_sources TO gb_app;
