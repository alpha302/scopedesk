-- +goose Up
ALTER TABLE assets ADD COLUMN classification jsonb;
ALTER TABLE assets ADD COLUMN category_override text;
ALTER TABLE assets ADD CONSTRAINT assets_classification_bounded CHECK
 (classification IS NULL OR (jsonb_typeof(classification)='object' AND octet_length(classification::text)<=8192));
ALTER TABLE assets ADD CONSTRAINT assets_category_override_bounded CHECK
 (category_override IS NULL OR octet_length(category_override) BETWEEN 1 AND 128);
-- NULL means legacy provenance is unknown. Do not infer manual/automatic origin.
-- +goose Down
ALTER TABLE assets DROP CONSTRAINT assets_category_override_bounded;
ALTER TABLE assets DROP CONSTRAINT assets_classification_bounded;
ALTER TABLE assets DROP COLUMN category_override;
ALTER TABLE assets DROP COLUMN classification;
