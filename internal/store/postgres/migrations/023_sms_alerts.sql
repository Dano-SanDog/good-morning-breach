ALTER TABLE alert_channel_settings
    ADD COLUMN sms_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN phone_e164 text CHECK (phone_e164 IS NULL OR phone_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    ADD COLUMN phone_verified_at timestamptz,
    ADD CONSTRAINT alert_channel_settings_sms_verified_check CHECK (NOT sms_enabled OR phone_verified_at IS NOT NULL),
    ADD CONSTRAINT alert_channel_settings_phone_check CHECK (phone_verified_at IS NULL OR phone_e164 IS NOT NULL);

CREATE TABLE phone_verifications (
    account_id bigint PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    phone_e164 text NOT NULL CHECK (phone_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    code_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    created_at timestamptz NOT NULL
);

ALTER TABLE alert_channel_state DROP CONSTRAINT alert_channel_state_channel_check;
ALTER TABLE alert_channel_state ADD CONSTRAINT alert_channel_state_channel_check
    CHECK (channel IN ('email', 'slack', 'sms'));

ALTER TABLE outbound_message_log DROP CONSTRAINT outbound_message_log_kind_check;
ALTER TABLE outbound_message_log ADD CONSTRAINT outbound_message_log_kind_check
    CHECK (kind IN ('sms_code', 'sms_alert', 'slack_test'));

ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_channel_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_channel_check
    CHECK (channel IN ('email', 'slack', 'sms'));

GRANT SELECT, INSERT, UPDATE, DELETE ON phone_verifications TO gb_app;
