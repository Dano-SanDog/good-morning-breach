GRANT DELETE ON stories TO gb_app;

CREATE INDEX stories_created_at_idx ON stories (created_at);


ALTER TABLE admin_audit_log
    DROP CONSTRAINT admin_audit_log_action_check;

ALTER TABLE admin_audit_log
    ADD CONSTRAINT admin_audit_log_action_check CHECK (action IN (
        'account_created', 'account_updated', 'account_deleted', 'account_totp_reset',
        'category_created', 'category_updated', 'category_deleted',
        'source_created', 'source_updated', 'source_deleted'
    ));

UPDATE data_sources SET poll_interval_seconds = 86400, updated_at = clock_timestamp()
    WHERE poll_interval_seconds > 86400
