-- Content-rights gate (FR-1.21, FR-8.8, FR-8.9, SC-023). Adds the "all rights
-- reserved" source type. Every existing source is a licensed source and already
-- headline_link, so the default keeps its behavior.
ALTER TABLE data_sources
    ADD COLUMN rights_class text NOT NULL DEFAULT 'licensed'
        CHECK (rights_class IN ('licensed', 'all_rights_reserved'));

ALTER TABLE data_sources
    ADD CONSTRAINT data_sources_all_rights_reserved_headline_only
        CHECK (rights_class <> 'all_rights_reserved' OR content_policy = 'headline_link');
