-- +goose Up
ALTER TABLE asset_services ADD COLUMN fingerprint_evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(fingerprint_evidence)='array' AND octet_length(fingerprint_evidence::text)<=65536);
ALTER TABLE assets ADD COLUMN fingerprint_evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(fingerprint_evidence)='array' AND octet_length(fingerprint_evidence::text)<=65536);
-- +goose Down
ALTER TABLE assets DROP COLUMN fingerprint_evidence;
ALTER TABLE asset_services DROP COLUMN fingerprint_evidence;
