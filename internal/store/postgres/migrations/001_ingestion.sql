CREATE TABLE data_sources (
    id text PRIMARY KEY,
    name text NOT NULL,
    address text NOT NULL CHECK (address ~ '^https://'),
    license_name text NOT NULL,
    license_url text NOT NULL CHECK (license_url ~ '^https://'),
    permitted_use text NOT NULL,
    attribution text NOT NULL,
    content_policy text NOT NULL CHECK (
        content_policy IN ('full_text', 'verbatim_excerpt', 'system_summary', 'headline_link')
    ),
    poll_interval_seconds bigint NOT NULL CHECK (poll_interval_seconds > 0),
    enabled boolean NOT NULL DEFAULT false,
    last_success_at timestamptz,
    last_failure_at timestamptz,
    last_failure_cause text CHECK (last_failure_cause IS NULL OR length(last_failure_cause) <= 500),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        NOT enabled OR (
            btrim(name) <> '' AND btrim(license_name) <> '' AND
            btrim(license_url) <> '' AND btrim(permitted_use) <> '' AND
            btrim(attribution) <> ''
        )
    )
);

CREATE TABLE stories (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    canonical_url text NOT NULL UNIQUE,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE story_sources (
    story_id bigint NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    source_id text NOT NULL REFERENCES data_sources(id) ON DELETE RESTRICT,
    first_collected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (story_id, source_id)
);

CREATE INDEX story_sources_source_idx ON story_sources (source_id, first_collected_at DESC);
CREATE INDEX stories_published_idx ON stories (published_at DESC NULLS LAST);

CREATE TABLE collection_runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id text NOT NULL REFERENCES data_sources(id) ON DELETE RESTRICT,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure')),
    items_received integer NOT NULL CHECK (items_received >= 0),
    items_saved integer NOT NULL CHECK (items_saved >= 0),
    items_skipped integer NOT NULL CHECK (items_skipped >= 0),
    failure_cause text CHECK (failure_cause IS NULL OR length(failure_cause) <= 500),
    CHECK ((outcome = 'success' AND failure_cause IS NULL) OR
           (outcome = 'failure' AND failure_cause IS NOT NULL))
);

CREATE INDEX collection_runs_source_started_idx
    ON collection_runs (source_id, started_at DESC);

INSERT INTO data_sources (
    id,
    name,
    address,
    license_name,
    license_url,
    permitted_use,
    attribution,
    content_policy,
    poll_interval_seconds,
    enabled
) VALUES (
    'cert-eu-security-advisories',
    'CERT-EU Security Advisories',
    'https://cert.europa.eu/publications/security-advisories-rss',
    'Creative Commons Attribution 4.0 International (CC BY 4.0)',
    'https://cert.europa.eu/legal-notice',
    'Reuse with appropriate credit and indication of changes. Third-party content may require separate permission.',
    'Source: CERT-EU. Licensed under CC BY 4.0. Titles are normalized to plain text.',
    'headline_link',
    86400,
    true
) ON CONFLICT (id) DO NOTHING;

GRANT USAGE ON SCHEMA public TO gb_app;
GRANT SELECT ON data_sources, stories, story_sources, collection_runs TO gb_app;
GRANT UPDATE (last_success_at, last_failure_at, last_failure_cause, updated_at)
    ON data_sources TO gb_app;
GRANT INSERT, UPDATE (title, published_at, updated_at) ON stories TO gb_app;
GRANT INSERT ON story_sources, collection_runs TO gb_app;
GRANT USAGE, SELECT ON SEQUENCE stories_id_seq, collection_runs_id_seq TO gb_app;
