CREATE TABLE alert_settings (
    account_id bigint PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    alert_time text NOT NULL CHECK (alert_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
    time_zone text NOT NULL CHECK (length(time_zone) BETWEEN 1 AND 100),
    days smallint[] NOT NULL CHECK (
        cardinality(days) BETWEEN 1 AND 7 AND
        days <@ ARRAY[0, 1, 2, 3, 4, 5, 6]::smallint[] AND
        array_position(days, NULL) IS NULL
    ),
    minimum_risk text NOT NULL CHECK (minimum_risk IN ('Critical', 'High', 'Medium', 'Low', 'Informational'))
);

GRANT SELECT, INSERT, UPDATE ON alert_settings TO gb_app;
