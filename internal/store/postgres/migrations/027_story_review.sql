-- Per-story review for conditional-license sources (FR-8.8). A story from a
-- "conditional" source shows its excerpt only after an admin approves that story.
ALTER TABLE data_sources DROP CONSTRAINT data_sources_rights_class_check;
ALTER TABLE data_sources
    ADD CONSTRAINT data_sources_rights_class_check
        CHECK (rights_class IN ('licensed', 'conditional', 'all_rights_reserved'));

ALTER TABLE stories
    ADD COLUMN excerpt_approved_at timestamptz,
    ADD COLUMN excerpt_approved_by bigint REFERENCES accounts(id) ON DELETE SET NULL;
GRANT UPDATE (excerpt_approved_at, excerpt_approved_by) ON stories TO gb_app;

ALTER TABLE admin_audit_log DROP CONSTRAINT admin_audit_log_action_check;
ALTER TABLE admin_audit_log
    ADD CONSTRAINT admin_audit_log_action_check CHECK (action IN (
        'account_created', 'account_updated', 'account_deleted',
        'category_created', 'category_updated', 'category_deleted',
        'source_created', 'source_updated', 'source_deleted',
        'account_totp_reset',
        'story_excerpt_approved', 'story_excerpt_revoked'
    ));

ALTER TABLE admin_audit_log DROP CONSTRAINT admin_audit_log_target_kind_check;
ALTER TABLE admin_audit_log
    ADD CONSTRAINT admin_audit_log_target_kind_check
        CHECK (target_kind IN ('account', 'category', 'source', 'story'));
