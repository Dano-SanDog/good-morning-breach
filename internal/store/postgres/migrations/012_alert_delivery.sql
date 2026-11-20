CREATE TABLE alert_state (
    account_id bigint PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    last_sent_slot_at timestamptz,
    last_alert_at timestamptz,
    retry_slot_at timestamptz,
    retry_attempts integer NOT NULL DEFAULT 0 CHECK (retry_attempts >= 0),
    last_attempt_at timestamptz
);

CREATE TABLE alert_deliveries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    channel text NOT NULL CHECK (channel IN ('email')),
    slot_at timestamptz NOT NULL,
    attempted_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure')),
    story_count integer NOT NULL CHECK (story_count >= 0),
    failure_cause text CHECK (failure_cause IS NULL OR length(failure_cause) <= 500),
    CHECK ((outcome = 'success') = (failure_cause IS NULL))
);

CREATE INDEX alert_deliveries_attempted_idx ON alert_deliveries (attempted_at);

GRANT SELECT, INSERT, UPDATE ON alert_state TO gb_app;
GRANT SELECT, INSERT, DELETE ON alert_deliveries TO gb_app;
GRANT USAGE, SELECT ON SEQUENCE alert_deliveries_id_seq TO gb_app;
