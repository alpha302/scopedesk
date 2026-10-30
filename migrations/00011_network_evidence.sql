-- +goose Up
ALTER TABLE assets ADD COLUMN network_evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(network_evidence)='array' AND octet_length(network_evidence::text)<=65536);
ALTER TABLE assets ADD COLUMN network_classified_at timestamptz;
CREATE INDEX assets_network_evidence ON assets USING gin(network_evidence jsonb_path_ops);
-- Historical is_cdn is left intact but is not verified evidence. Fresh classification replaces it.
-- +goose Down
DROP INDEX assets_network_evidence;
ALTER TABLE assets DROP COLUMN network_classified_at;
ALTER TABLE assets DROP COLUMN network_evidence;
