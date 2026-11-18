ALTER TABLE stories
    ADD COLUMN risk text NOT NULL DEFAULT 'Informational'
        CHECK (risk IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    ADD COLUMN sentiment text NOT NULL DEFAULT 'Neutral'
        CHECK (sentiment IN ('Negative', 'Neutral', 'Positive'));

CREATE TABLE categories (
    id text PRIMARY KEY CHECK (id ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    name text NOT NULL UNIQUE CHECK (length(btrim(name)) BETWEEN 1 AND 80),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO categories (id, name) VALUES
    ('vulnerability', 'Vulnerability'),
    ('exploited-vulnerability', 'Exploited Vulnerability'),
    ('ransomware', 'Ransomware'),
    ('malware', 'Malware'),
    ('data-breach', 'Data Breach'),
    ('phishing-social-engineering', 'Phishing and Social Engineering'),
    ('nation-state-activity', 'Nation-State Activity'),
    ('supply-chain', 'Supply Chain'),
    ('cloud-infrastructure', 'Cloud and Infrastructure'),
    ('internet-outage-ddos', 'Internet Outage and DDoS'),
    ('policy-regulation', 'Policy and Regulation'),
    ('other', 'Other');

CREATE TABLE story_categories (
    story_id bigint NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    category_id text NOT NULL REFERENCES categories(id) ON DELETE RESTRICT,
    PRIMARY KEY (story_id, category_id)
);

INSERT INTO story_categories (story_id, category_id)
    SELECT id, 'other' FROM stories
    ON CONFLICT DO NOTHING;

CREATE INDEX story_categories_category_idx ON story_categories (category_id, story_id);

GRANT SELECT ON categories TO gb_app;
GRANT SELECT, INSERT, DELETE ON story_categories TO gb_app;
GRANT UPDATE (risk, sentiment) ON stories TO gb_app;
