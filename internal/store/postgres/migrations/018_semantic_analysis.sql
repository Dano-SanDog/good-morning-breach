ALTER TABLE stories
    ADD COLUMN analysis_engine text NOT NULL DEFAULT 'baseline'
        CHECK (analysis_engine IN ('baseline', 'semantic')),
    ADD COLUMN analysis_confidence smallint NOT NULL DEFAULT 0
        CHECK (analysis_confidence BETWEEN 0 AND 100);

CREATE TABLE story_cves (
    story_id bigint NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,7}$'),
    PRIMARY KEY (story_id, cve_id)
);

CREATE INDEX story_cves_cve_idx ON story_cves (cve_id, story_id);

GRANT SELECT, INSERT, DELETE ON story_cves TO gb_app;
GRANT UPDATE (analysis_engine, analysis_confidence) ON stories TO gb_app;
