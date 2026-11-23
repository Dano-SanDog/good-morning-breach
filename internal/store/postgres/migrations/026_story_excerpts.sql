-- Verbatim story excerpts (FR-4.12, FR-5.2, FR-5.5). Written only for sources whose
-- content rule permits an excerpt. Every read goes through contentrights.Gate.
ALTER TABLE stories ADD COLUMN excerpt text CHECK (excerpt IS NULL OR char_length(excerpt) <= 500);
GRANT UPDATE (excerpt) ON stories TO gb_app;
