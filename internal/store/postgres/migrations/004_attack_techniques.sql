ALTER TABLE stories
    ADD COLUMN analysis_version integer NOT NULL DEFAULT 0
        CHECK (analysis_version >= 0);

CREATE TABLE attack_techniques (
    technique_id text PRIMARY KEY
        CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    tactics text[] NOT NULL CHECK (cardinality(tactics) > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE story_techniques (
    story_id bigint NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    technique_id text NOT NULL REFERENCES attack_techniques(technique_id) ON DELETE RESTRICT,
    PRIMARY KEY (story_id, technique_id)
);

CREATE INDEX story_techniques_technique_idx ON story_techniques (technique_id, story_id);

GRANT SELECT, INSERT, DELETE ON story_techniques TO gb_app;
GRANT SELECT, INSERT ON attack_techniques TO gb_app;
GRANT UPDATE (name, tactics, updated_at) ON attack_techniques TO gb_app;
GRANT UPDATE (analysis_version, risk, sentiment, updated_at) ON stories TO gb_app;
