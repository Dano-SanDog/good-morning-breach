-- Removes SMS alerts. Safe on a database that has applied 023 and on one where
-- these objects are already gone.
DELETE FROM alert_channel_state WHERE channel = 'sms';
DELETE FROM alert_deliveries WHERE channel = 'sms';
DELETE FROM outbound_message_log WHERE kind <> 'slack_test';

DROP TABLE IF EXISTS phone_verifications;

ALTER TABLE alert_channel_settings
    DROP CONSTRAINT IF EXISTS alert_channel_settings_sms_verified_check,
    DROP CONSTRAINT IF EXISTS alert_channel_settings_phone_check,
    DROP COLUMN IF EXISTS sms_enabled,
    DROP COLUMN IF EXISTS phone_e164,
    DROP COLUMN IF EXISTS phone_verified_at;

ALTER TABLE alert_channel_state DROP CONSTRAINT IF EXISTS alert_channel_state_channel_check;
ALTER TABLE alert_channel_state ADD CONSTRAINT alert_channel_state_channel_check
    CHECK (channel IN ('email', 'slack'));

ALTER TABLE outbound_message_log DROP CONSTRAINT IF EXISTS outbound_message_log_kind_check;
ALTER TABLE outbound_message_log ADD CONSTRAINT outbound_message_log_kind_check
    CHECK (kind IN ('slack_test'));

ALTER TABLE alert_deliveries DROP CONSTRAINT IF EXISTS alert_deliveries_channel_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_channel_check
    CHECK (channel IN ('email', 'slack'));
