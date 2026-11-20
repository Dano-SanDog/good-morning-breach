CREATE TABLE alert_channel_settings (
    account_id bigint PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    email_enabled boolean NOT NULL DEFAULT true,
    slack_enabled boolean NOT NULL DEFAULT false,
    slack_webhook_sealed bytea,
    CHECK (NOT slack_enabled OR slack_webhook_sealed IS NOT NULL)
);

CREATE TABLE alert_channel_state (
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    channel text NOT NULL CHECK (channel IN ('email', 'slack')),
    last_sent_slot_at timestamptz,
    last_alert_at timestamptz,
    retry_slot_at timestamptz,
    retry_attempts integer NOT NULL DEFAULT 0 CHECK (retry_attempts >= 0),
    last_attempt_at timestamptz,
    PRIMARY KEY (account_id, channel)
);

INSERT INTO alert_channel_state
    (account_id, channel, last_sent_slot_at, last_alert_at, retry_slot_at, retry_attempts, last_attempt_at)
SELECT account_id, 'email', last_sent_slot_at, last_alert_at, retry_slot_at, retry_attempts, last_attempt_at
FROM alert_state;

CREATE TABLE outbound_message_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('slack_test')),
    sent_at timestamptz NOT NULL
);

CREATE INDEX outbound_message_log_account_idx ON outbound_message_log (account_id, kind, sent_at);
CREATE INDEX outbound_message_log_sent_idx ON outbound_message_log (sent_at);

ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_channel_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_channel_check
    CHECK (channel IN ('email', 'slack'));

GRANT SELECT, INSERT, UPDATE ON alert_channel_settings TO gb_app;
GRANT SELECT, INSERT, UPDATE ON alert_channel_state TO gb_app;
GRANT SELECT, INSERT, DELETE ON outbound_message_log TO gb_app;
GRANT USAGE, SELECT ON SEQUENCE outbound_message_log_id_seq TO gb_app;
